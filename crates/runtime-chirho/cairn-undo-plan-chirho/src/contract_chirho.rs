// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Closed canonical blessed-reversion contracts and capability views.

use crate::framing_chirho::validate_hash_chirho;
use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::{CapabilityChirho, HashChirho, NodeDefChirho};
use cairn_input_projection_chirho::field_graph_chirho::PrivacyClassChirho;
use cairn_ledger_model_chirho::asset_op_chirho::ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const REVERSION_CONTRACT_SET_SCHEMA_CHIRHO: &str = "blessed-reversion-contract-set-v1-chirho";
pub const REVERSION_CONTRACT_SCHEMA_CHIRHO: &str = "blessed-reversion-contract-v1-chirho";
pub const POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO: &str = "postgres_reversible_chirho";
/// The served spend-bounded LLM paid-effect subtype. `effect_chirho.rs` routes a
/// `PaidEffectChirho { effect_chirho: LLM_SERVED_EFFECT_SUBTYPE_CHIRHO }` capability to the CF3
/// money ladder in `llm_served_chirho.rs`, mirroring the reversible-PostgreSQL subtype above.
pub const LLM_SERVED_EFFECT_SUBTYPE_CHIRHO: &str = "llm_chirho";
pub const MAX_REVERSION_CONTRACTS_CHIRHO: usize = 128;
pub const MAX_UNDO_STEPS_PER_CONTRACT_CHIRHO: usize = 64;
pub const MAX_UNDO_EVIDENCE_KINDS_CHIRHO: usize = 32;
pub const MAX_CONFIG_PORTS_PER_CONTRACT_CHIRHO: usize = 64;
pub const MAX_ASSET_OP_PORTS_PER_CONTRACT_CHIRHO: usize = 1;
pub const MAX_COMPENSATION_CASCADE_DEPTH_CHIRHO: u16 = 32;
pub const MAX_CONTRACT_LABEL_BYTES_CHIRHO: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlessedContractKeyChirho(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlessedReversionContractSetChirho {
    pub schema_chirho: String,
    pub max_depth_chirho: u16,
    pub contracts_chirho: Vec<BlessedReversionContractChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlessedReversionContractChirho {
    pub schema_chirho: String,
    pub contract_key_chirho: BlessedContractKeyChirho,
    pub effect_selector_chirho: EffectDoorSelectorChirho,
    pub supporting_requirements_chirho: Vec<SupportingCapabilityRequirementChirho>,
    pub produced_evidence_chirho: Vec<UndoEvidenceKindChirho>,
    pub disposition_chirho: UndoDispositionChirho,
    pub privacy_floor_chirho: PrivacyClassChirho,
    pub max_depth_chirho: u16,
    pub config_ports_chirho: Vec<ConfigPortRequirementChirho>,
    /// Checked money-request ports. Empty preserves every pre-AssetOp contract byte-for-byte.
    ///
    /// Descriptor-v2 v1 executes one request value per effect door, so one contract may name at
    /// most one AssetOp port. A future multi-request runtime requires a reviewed schema revision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asset_op_ports_chirho: Vec<AssetOpPortRequirementChirho>,
    /// Provider reconciliation required by this signed contract. Absent keeps every pre-P2
    /// contract byte-identical and grants no reconciliation authority by inference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation_requirement_chirho: Option<EffectReconciliationRequirementChirho>,
    /// Pricing authority required by this signed contract. Actual `AssetOpChirho` values remain
    /// runtime evidence and never become caller-selected contract law.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing_source_requirement_chirho: Option<EffectPricingSourceRequirementChirho>,
    /// Cache behavior is signed law. Runtime subtype inference may not authorize reuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_result_cache_posture_chirho: Option<EffectResultCachePostureChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum EffectReconciliationRequirementChirho {
    #[serde(rename = "query-by-effect-key-chirho")]
    QueryByEffectKeyChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum EffectPricingSourceRequirementChirho {
    #[serde(rename = "verified-price-book-chirho")]
    VerifiedPriceBookChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum EffectResultCachePostureChirho {
    #[serde(rename = "never-reuse-effect-result-chirho")]
    NeverReuseEffectResultChirho,
    #[serde(rename = "verified-reuse-chirho")]
    VerifiedReuseChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum EffectDoorSelectorChirho {
    #[serde(rename = "clock-chirho")]
    ClockChirho,
    #[serde(rename = "random-chirho")]
    RandomChirho,
    #[serde(rename = "read-store-chirho")]
    ReadStoreChirho,
    #[serde(rename = "write-store-chirho")]
    WriteStoreChirho,
    #[serde(rename = "paid-effect-chirho")]
    PaidEffectChirho { effect_chirho: String },
    #[serde(rename = "query-chirho")]
    QueryChirho,
    #[serde(rename = "net-chirho")]
    NetChirho,
    #[serde(rename = "secret-ref-chirho")]
    SecretRefChirho,
    #[serde(rename = "realtime-session-chirho")]
    RealtimeSessionChirho,
    #[serde(rename = "invoke-chirho")]
    InvokeChirho,
    #[serde(rename = "template-app-deploy-chirho")]
    TemplateAppDeployChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum SupportingCapabilityRequirementChirho {
    #[serde(rename = "query-caller-identity-chirho")]
    QueryCallerIdentityChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum UndoEvidenceKindChirho {
    #[serde(rename = "effect-idempotency-key-chirho")]
    EffectIdempotencyKeyChirho,
    #[serde(rename = "request-ref-chirho")]
    RequestRefChirho,
    #[serde(rename = "response-ref-chirho")]
    ResponseRefChirho,
    #[serde(rename = "before-image-ref-chirho")]
    BeforeImageRefChirho,
    #[serde(rename = "post-state-fingerprint-chirho")]
    PostStateFingerprintChirho,
    #[serde(rename = "previous-head-ref-chirho")]
    PreviousHeadRefChirho,
    #[serde(rename = "provider-receipt-ref-chirho")]
    ProviderReceiptRefChirho,
    #[serde(rename = "authority-evidence-ref-chirho")]
    AuthorityEvidenceRefChirho,
    #[serde(rename = "subject-ref-chirho")]
    SubjectRefChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum UndoDispositionChirho {
    #[serde(rename = "observation-only-chirho")]
    ObservationOnlyChirho {
        reason_code_chirho: ObservationReasonChirho,
    },
    #[serde(rename = "compensable-chirho")]
    CompensableChirho {
        steps_chirho: Vec<UndoStepTemplateChirho>,
        residuals_chirho: Vec<IrreversibleResidualChirho>,
        #[serde(skip_serializing_if = "Option::is_none")]
        admission_gate_chirho: Option<HashChirho>,
    },
    #[serde(rename = "irreversible-gated-chirho")]
    IrreversibleGatedChirho {
        residuals_chirho: Vec<IrreversibleResidualChirho>,
        admission_gate_chirho: HashChirho,
        remediation_chirho: HashChirho,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationReasonChirho {
    #[serde(rename = "read-only-capability-chirho")]
    ReadOnlyCapabilityChirho,
    #[serde(rename = "recorded-nondeterminism-chirho")]
    RecordedNondeterminismChirho,
    #[serde(rename = "authority-handle-only-chirho")]
    AuthorityHandleOnlyChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UndoStepTemplateChirho {
    pub action_chirho: UndoActionChirho,
    pub required_evidence_chirho: Vec<UndoEvidenceKindChirho>,
    pub verification_chirho: UndoVerificationModeChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UndoActionChirho {
    #[serde(rename = "conditional-restore-chirho")]
    ConditionalRestoreChirho,
    #[serde(rename = "conditional-delete-chirho")]
    ConditionalDeleteChirho,
    #[serde(rename = "corrective-forward-chirho")]
    CorrectiveForwardChirho,
    #[serde(rename = "manual-remediation-chirho")]
    ManualRemediationChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UndoVerificationModeChirho {
    #[serde(rename = "verify-post-fingerprint-chirho")]
    VerifyPostFingerprintChirho,
    #[serde(rename = "verify-provider-receipt-chirho")]
    VerifyProviderReceiptChirho,
    #[serde(rename = "verify-authority-evidence-chirho")]
    VerifyAuthorityEvidenceChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IrreversibleResidualChirho {
    #[serde(rename = "caller-exposure-chirho")]
    CallerExposureChirho,
    #[serde(rename = "provider-work-consumed-chirho")]
    ProviderWorkConsumedChirho,
    #[serde(rename = "external-visibility-chirho")]
    ExternalVisibilityChirho,
    #[serde(rename = "published-url-observed-chirho")]
    PublishedUrlObservedChirho,
    #[serde(rename = "forward-only-authority-record-chirho")]
    ForwardOnlyAuthorityRecordChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigPortRequirementChirho {
    pub port_chirho: String,
    pub privacy_floor_chirho: PrivacyClassChirho,
}

/// One exact node input that a reviewed money door consumes as canonical `AssetOpChirho` bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetOpPortRequirementChirho {
    pub port_chirho: String,
    pub schema_chirho: HashChirho,
}

/// A language-neutral, explicitly labelled view of the core capability wire.
///
/// Both the complete-multiset and selected-effect components of a door fingerprint use this exact
/// encoder. They never serialize `CapabilityChirho` through separate paths.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum CanonicalCapabilityChirho {
    #[serde(rename = "read-store-chirho")]
    ReadStoreChirho { prefix_chirho: String },
    #[serde(rename = "write-store-chirho")]
    WriteStoreChirho { prefix_chirho: String },
    #[serde(rename = "paid-effect-chirho")]
    PaidEffectChirho {
        effect_chirho: String,
        caller_chirho: String,
    },
    #[serde(rename = "user-identity-chirho")]
    UserIdentityChirho {
        principal_chirho: String,
        client_id_chirho: String,
        token_hash_chirho: String,
    },
    #[serde(rename = "app-context-chirho")]
    AppContextChirho {
        app_chirho: String,
        owner_principal_chirho: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        price_book_chirho: Option<HashChirho>,
        #[serde(skip_serializing_if = "Option::is_none")]
        billing_policy_chirho: Option<HashChirho>,
    },
    #[serde(rename = "secret-ref-chirho")]
    SecretRefChirho { name_chirho: String },
    #[serde(rename = "realtime-session-chirho")]
    RealtimeSessionChirho {
        app_chirho: String,
        caller_chirho: String,
    },
    #[serde(rename = "support-issue-chirho")]
    SupportIssueChirho {
        issue_chirho: String,
        actions_chirho: Vec<String>,
    },
    #[serde(rename = "causal-reversion-chirho")]
    CausalReversionChirho { branch_chirho: String },
    #[serde(rename = "net-chirho")]
    NetChirho { allowlist_chirho: Vec<String> },
    #[serde(rename = "query-chirho")]
    QueryChirho {
        prefix_chirho: String,
        caller_chirho: String,
        max_rows_chirho: u64,
    },
    #[serde(rename = "clock-chirho")]
    ClockChirho,
    #[serde(rename = "random-chirho")]
    RandomChirho,
    #[serde(rename = "invoke-chirho")]
    InvokeChirho { node_chirho: HashChirho },
    #[serde(rename = "template-app-deploy-chirho")]
    TemplateAppDeployChirho { template_id_chirho: String },
}

impl CanonicalCapabilityChirho {
    pub fn try_from_core_chirho(capability_chirho: &CapabilityChirho) -> Result<Self> {
        let canonical_chirho = match capability_chirho {
            CapabilityChirho::ReadStoreChirho { prefix_chirho } => Self::ReadStoreChirho {
                prefix_chirho: prefix_chirho.clone(),
            },
            CapabilityChirho::WriteStoreChirho { prefix_chirho } => Self::WriteStoreChirho {
                prefix_chirho: prefix_chirho.clone(),
            },
            CapabilityChirho::PaidEffectChirho {
                effect_chirho,
                caller_chirho,
            } => Self::PaidEffectChirho {
                effect_chirho: effect_chirho.clone(),
                caller_chirho: caller_chirho.clone(),
            },
            CapabilityChirho::UserIdentityChirho {
                principal_chirho,
                client_id_chirho,
                token_hash_chirho,
            } => Self::UserIdentityChirho {
                principal_chirho: principal_chirho.clone(),
                client_id_chirho: client_id_chirho.clone(),
                token_hash_chirho: token_hash_chirho.clone(),
            },
            CapabilityChirho::AppContextChirho {
                app_chirho,
                owner_principal_chirho,
                price_book_chirho,
                billing_policy_chirho,
            } => Self::AppContextChirho {
                app_chirho: app_chirho.clone(),
                owner_principal_chirho: owner_principal_chirho.clone(),
                price_book_chirho: price_book_chirho.clone(),
                billing_policy_chirho: billing_policy_chirho.clone(),
            },
            CapabilityChirho::SecretRefChirho { name_chirho } => Self::SecretRefChirho {
                name_chirho: name_chirho.clone(),
            },
            CapabilityChirho::RealtimeSessionChirho {
                app_chirho,
                caller_chirho,
            } => Self::RealtimeSessionChirho {
                app_chirho: app_chirho.clone(),
                caller_chirho: caller_chirho.clone(),
            },
            CapabilityChirho::SupportIssueChirho {
                issue_chirho,
                actions_chirho,
            } => Self::SupportIssueChirho {
                issue_chirho: issue_chirho.clone(),
                actions_chirho: sorted_strings_chirho(actions_chirho)?,
            },
            CapabilityChirho::CausalReversionChirho { branch_chirho } => {
                Self::CausalReversionChirho {
                    branch_chirho: branch_chirho.clone(),
                }
            }
            CapabilityChirho::NetChirho { allowlist_chirho } => Self::NetChirho {
                allowlist_chirho: sorted_strings_chirho(allowlist_chirho)?,
            },
            CapabilityChirho::QueryChirho {
                prefix_chirho,
                caller_chirho,
                max_rows_chirho,
            } => Self::QueryChirho {
                prefix_chirho: prefix_chirho.clone(),
                caller_chirho: caller_chirho.clone(),
                max_rows_chirho: *max_rows_chirho,
            },
            CapabilityChirho::ClockChirho => Self::ClockChirho,
            CapabilityChirho::RandomChirho => Self::RandomChirho,
            CapabilityChirho::InvokeChirho { node_chirho } => Self::InvokeChirho {
                node_chirho: node_chirho.clone(),
            },
            CapabilityChirho::TemplateAppDeployChirho { template_id_chirho } => {
                Self::TemplateAppDeployChirho {
                    template_id_chirho: template_id_chirho.clone(),
                }
            }
        };
        validate_canonical_capability_chirho(&canonical_chirho)?;
        Ok(canonical_chirho)
    }
}

pub fn canonicalize_capabilities_chirho(
    capabilities_chirho: &[CapabilityChirho],
) -> Result<Vec<CanonicalCapabilityChirho>> {
    let mut canonical_chirho = capabilities_chirho
        .iter()
        .map(CanonicalCapabilityChirho::try_from_core_chirho)
        .collect::<Result<Vec<_>>>()?;
    canonical_chirho.sort();
    if canonical_chirho
        .windows(2)
        .any(|pair_chirho| pair_chirho[0] == pair_chirho[1])
    {
        bail!("exact duplicate capabilities are forbidden in one node multiset");
    }
    Ok(canonical_chirho)
}

pub fn canonical_capability_multiset_bytes_chirho(
    capabilities_chirho: &[CanonicalCapabilityChirho],
) -> Result<Vec<u8>> {
    validate_canonical_capability_multiset_chirho(capabilities_chirho)?;
    serde_json::to_vec(capabilities_chirho).context("encode canonical capability multiset")
}

pub fn canonical_capability_bytes_chirho(
    capability_chirho: &CanonicalCapabilityChirho,
) -> Result<Vec<u8>> {
    validate_canonical_capability_chirho(capability_chirho)?;
    serde_json::to_vec(capability_chirho).context("encode canonical capability")
}

/// The canonical authoring contract set, including the local-proof Descriptor-D PostgreSQL door
/// and the least-authority store-read door.
///
/// Existing contract objects remain byte-identical when another contract is added. PostgreSQL
/// authority exists only when descriptor-v2 admission resolves its exact contract and the runtime
/// composes its open-only provider; an unmatched or uncomposed capability fails closed.
pub fn canonical_authoring_reversion_contract_set_chirho() -> BlessedReversionContractSetChirho {
    let mut contracts_chirho = vec![
        builtin_llm_contract_chirho(),
        builtin_postgres_reversible_contract_chirho(),
        builtin_query_contract_chirho(),
        builtin_read_store_contract_chirho(),
        builtin_template_deploy_contract_chirho(),
        builtin_write_store_contract_chirho(),
    ];
    contracts_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho
            .contract_key_chirho
            .cmp(&right_chirho.contract_key_chirho)
    });
    BlessedReversionContractSetChirho {
        schema_chirho: REVERSION_CONTRACT_SET_SCHEMA_CHIRHO.to_string(),
        max_depth_chirho: 8,
        contracts_chirho,
    }
}

pub fn validate_reversion_contract_set_chirho(
    set_chirho: &BlessedReversionContractSetChirho,
) -> Result<()> {
    if set_chirho.schema_chirho != REVERSION_CONTRACT_SET_SCHEMA_CHIRHO {
        bail!("unsupported blessed-reversion contract-set schema");
    }
    if set_chirho.max_depth_chirho == 0
        || set_chirho.max_depth_chirho > MAX_COMPENSATION_CASCADE_DEPTH_CHIRHO
    {
        bail!("contract-set cascade depth is outside the engine bound");
    }
    if set_chirho.contracts_chirho.is_empty()
        || set_chirho.contracts_chirho.len() > MAX_REVERSION_CONTRACTS_CHIRHO
    {
        bail!("contract set must be nonempty and bounded");
    }

    let mut previous_key_chirho: Option<&BlessedContractKeyChirho> = None;
    let mut pattern_bytes_chirho = BTreeSet::new();
    for contract_chirho in &set_chirho.contracts_chirho {
        validate_reversion_contract_chirho(contract_chirho, set_chirho.max_depth_chirho)?;
        if let Some(previous_chirho) = previous_key_chirho {
            if previous_chirho >= &contract_chirho.contract_key_chirho {
                bail!("contract set must be strictly byte-sorted by unique contract key");
            }
        }
        previous_key_chirho = Some(&contract_chirho.contract_key_chirho);
        let pattern_chirho = serde_json::to_vec(&(
            &contract_chirho.effect_selector_chirho,
            &contract_chirho.supporting_requirements_chirho,
        ))
        .context("encode contract capability pattern")?;
        if !pattern_bytes_chirho.insert(pattern_chirho) {
            bail!("two contract keys are reachable from one byte-identical capability pattern");
        }
    }
    Ok(())
}

pub fn validate_reversion_contract_chirho(
    contract_chirho: &BlessedReversionContractChirho,
    set_max_depth_chirho: u16,
) -> Result<()> {
    if contract_chirho.schema_chirho != REVERSION_CONTRACT_SCHEMA_CHIRHO {
        bail!("unsupported blessed-reversion contract schema");
    }
    validate_label_chirho(&contract_chirho.contract_key_chirho.0, "contract key")?;
    validate_selector_chirho(&contract_chirho.effect_selector_chirho)?;
    validate_supporting_requirements_chirho(contract_chirho)?;
    validate_sorted_unique_chirho(
        &contract_chirho.produced_evidence_chirho,
        MAX_UNDO_EVIDENCE_KINDS_CHIRHO,
        "produced evidence",
    )?;
    if contract_chirho.max_depth_chirho == 0
        || contract_chirho.max_depth_chirho > set_max_depth_chirho
    {
        bail!("contract cascade depth exceeds its canonical set");
    }
    validate_config_ports_chirho(&contract_chirho.config_ports_chirho)?;
    validate_asset_op_ports_chirho(&contract_chirho.asset_op_ports_chirho)?;
    validate_disposition_chirho(contract_chirho)?;

    let private_caller_effect_chirho = matches!(
        contract_chirho.effect_selector_chirho,
        EffectDoorSelectorChirho::QueryChirho
    ) || matches!(
        &contract_chirho.effect_selector_chirho,
        EffectDoorSelectorChirho::PaidEffectChirho { effect_chirho }
            if effect_chirho == "llm_chirho"
    );
    if private_caller_effect_chirho
        && contract_chirho.privacy_floor_chirho != PrivacyClassChirho::DirectChirho
    {
        bail!("query and LLM contracts require the DirectChirho privacy floor");
    }
    match &contract_chirho.effect_selector_chirho {
        EffectDoorSelectorChirho::QueryChirho => require_residual_chirho(
            &contract_chirho.disposition_chirho,
            IrreversibleResidualChirho::CallerExposureChirho,
            "query",
        )?,
        EffectDoorSelectorChirho::PaidEffectChirho { effect_chirho }
            if effect_chirho == "llm_chirho" =>
        {
            require_residual_chirho(
                &contract_chirho.disposition_chirho,
                IrreversibleResidualChirho::ProviderWorkConsumedChirho,
                "LLM",
            )?
        }
        EffectDoorSelectorChirho::TemplateAppDeployChirho => {
            require_residual_chirho(
                &contract_chirho.disposition_chirho,
                IrreversibleResidualChirho::PublishedUrlObservedChirho,
                "template deploy",
            )?;
            require_residual_chirho(
                &contract_chirho.disposition_chirho,
                IrreversibleResidualChirho::ForwardOnlyAuthorityRecordChirho,
                "template deploy",
            )?;
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn selector_matches_capability_chirho(
    selector_chirho: &EffectDoorSelectorChirho,
    capability_chirho: &CanonicalCapabilityChirho,
) -> bool {
    match (selector_chirho, capability_chirho) {
        (EffectDoorSelectorChirho::ClockChirho, CanonicalCapabilityChirho::ClockChirho)
        | (EffectDoorSelectorChirho::RandomChirho, CanonicalCapabilityChirho::RandomChirho)
        | (
            EffectDoorSelectorChirho::ReadStoreChirho,
            CanonicalCapabilityChirho::ReadStoreChirho { .. },
        )
        | (
            EffectDoorSelectorChirho::WriteStoreChirho,
            CanonicalCapabilityChirho::WriteStoreChirho { .. },
        )
        | (EffectDoorSelectorChirho::QueryChirho, CanonicalCapabilityChirho::QueryChirho { .. })
        | (EffectDoorSelectorChirho::NetChirho, CanonicalCapabilityChirho::NetChirho { .. })
        | (
            EffectDoorSelectorChirho::SecretRefChirho,
            CanonicalCapabilityChirho::SecretRefChirho { .. },
        )
        | (
            EffectDoorSelectorChirho::RealtimeSessionChirho,
            CanonicalCapabilityChirho::RealtimeSessionChirho { .. },
        )
        | (
            EffectDoorSelectorChirho::InvokeChirho,
            CanonicalCapabilityChirho::InvokeChirho { .. },
        )
        | (
            EffectDoorSelectorChirho::TemplateAppDeployChirho,
            CanonicalCapabilityChirho::TemplateAppDeployChirho { .. },
        ) => true,
        (
            EffectDoorSelectorChirho::PaidEffectChirho {
                effect_chirho: selector_effect_chirho,
            },
            CanonicalCapabilityChirho::PaidEffectChirho {
                effect_chirho: capability_effect_chirho,
                ..
            },
        ) => selector_effect_chirho == capability_effect_chirho,
        _ => false,
    }
}

pub(crate) fn supporting_requirement_matches_chirho(
    requirement_chirho: &SupportingCapabilityRequirementChirho,
    effect_capability_chirho: &CanonicalCapabilityChirho,
    candidate_chirho: &CanonicalCapabilityChirho,
) -> bool {
    match (
        requirement_chirho,
        effect_capability_chirho,
        candidate_chirho,
    ) {
        (
            SupportingCapabilityRequirementChirho::QueryCallerIdentityChirho,
            CanonicalCapabilityChirho::QueryChirho { caller_chirho, .. },
            CanonicalCapabilityChirho::UserIdentityChirho {
                principal_chirho, ..
            },
        ) => caller_chirho == principal_chirho,
        _ => false,
    }
}

fn validate_disposition_chirho(contract_chirho: &BlessedReversionContractChirho) -> Result<()> {
    match &contract_chirho.disposition_chirho {
        UndoDispositionChirho::ObservationOnlyChirho { .. } => {
            if !selector_is_structural_observation_chirho(&contract_chirho.effect_selector_chirho)
                || !contract_chirho.supporting_requirements_chirho.is_empty()
            {
                bail!("observation-only legality must follow the closed read-only capability set");
            }
        }
        UndoDispositionChirho::CompensableChirho {
            steps_chirho,
            residuals_chirho,
            admission_gate_chirho,
        } => {
            if steps_chirho.is_empty() || steps_chirho.len() > MAX_UNDO_STEPS_PER_CONTRACT_CHIRHO {
                bail!("compensable contract steps must be nonempty and bounded");
            }
            if residuals_chirho.is_empty() != admission_gate_chirho.is_none() {
                bail!("compensable residuals and admission gate must appear together");
            }
            if let Some(gate_chirho) = admission_gate_chirho {
                validate_hash_chirho(gate_chirho, "compensable admission gate")?;
            }
            validate_sorted_unique_chirho(residuals_chirho, 16, "irreversible residuals")?;
            for step_chirho in steps_chirho {
                validate_undo_step_chirho(step_chirho, &contract_chirho.produced_evidence_chirho)?;
            }
        }
        UndoDispositionChirho::IrreversibleGatedChirho {
            residuals_chirho,
            admission_gate_chirho,
            remediation_chirho,
        } => {
            if residuals_chirho.is_empty() {
                bail!("irreversible-gated contract requires at least one residual");
            }
            validate_sorted_unique_chirho(residuals_chirho, 16, "irreversible residuals")?;
            validate_hash_chirho(admission_gate_chirho, "irreversible admission gate")?;
            validate_hash_chirho(remediation_chirho, "terminal remediation template")?;
        }
    }
    Ok(())
}

fn validate_undo_step_chirho(
    step_chirho: &UndoStepTemplateChirho,
    produced_evidence_chirho: &[UndoEvidenceKindChirho],
) -> Result<()> {
    validate_sorted_unique_chirho(
        &step_chirho.required_evidence_chirho,
        MAX_UNDO_EVIDENCE_KINDS_CHIRHO,
        "step evidence",
    )?;
    if step_chirho
        .required_evidence_chirho
        .iter()
        .any(|kind_chirho| !produced_evidence_chirho.contains(kind_chirho))
    {
        bail!("compensation step requires evidence its effect contract does not produce");
    }
    Ok(())
}

fn require_residual_chirho(
    disposition_chirho: &UndoDispositionChirho,
    required_chirho: IrreversibleResidualChirho,
    label_chirho: &str,
) -> Result<()> {
    let residuals_chirho = match disposition_chirho {
        UndoDispositionChirho::CompensableChirho {
            residuals_chirho,
            admission_gate_chirho: Some(_),
            ..
        }
        | UndoDispositionChirho::IrreversibleGatedChirho {
            residuals_chirho, ..
        } => residuals_chirho,
        _ => bail!("{label_chirho} contract requires an irreversible gate"),
    };
    if !residuals_chirho.contains(&required_chirho) {
        bail!("{label_chirho} contract omits its required irreversible residual");
    }
    Ok(())
}

fn validate_supporting_requirements_chirho(
    contract_chirho: &BlessedReversionContractChirho,
) -> Result<()> {
    validate_sorted_unique_chirho(
        &contract_chirho.supporting_requirements_chirho,
        8,
        "supporting capability requirements",
    )?;
    match &contract_chirho.effect_selector_chirho {
        EffectDoorSelectorChirho::QueryChirho => {
            if contract_chirho.supporting_requirements_chirho
                != [SupportingCapabilityRequirementChirho::QueryCallerIdentityChirho]
            {
                bail!("query contract requires exactly its caller identity capability");
            }
        }
        _ if !contract_chirho.supporting_requirements_chirho.is_empty() => {
            bail!("this v1 effect selector does not admit supporting capabilities");
        }
        _ => {}
    }
    Ok(())
}

fn validate_config_ports_chirho(ports_chirho: &[ConfigPortRequirementChirho]) -> Result<()> {
    if ports_chirho.len() > MAX_CONFIG_PORTS_PER_CONTRACT_CHIRHO {
        bail!("contract config-port count exceeds the engine bound");
    }
    let mut previous_chirho: Option<&str> = None;
    for port_chirho in ports_chirho {
        validate_label_chirho(&port_chirho.port_chirho, "config port")?;
        if previous_chirho
            .is_some_and(|value_chirho| value_chirho >= port_chirho.port_chirho.as_str())
        {
            bail!("config ports must be strictly byte-sorted and unique");
        }
        previous_chirho = Some(&port_chirho.port_chirho);
    }
    Ok(())
}

fn validate_asset_op_ports_chirho(ports_chirho: &[AssetOpPortRequirementChirho]) -> Result<()> {
    if ports_chirho.len() > MAX_ASSET_OP_PORTS_PER_CONTRACT_CHIRHO {
        bail!("descriptor-v2 v1 admits at most one AssetOp request port per effect contract");
    }
    let mut previous_chirho: Option<&str> = None;
    for port_chirho in ports_chirho {
        validate_label_chirho(&port_chirho.port_chirho, "AssetOp port")?;
        validate_hash_chirho(&port_chirho.schema_chirho, "AssetOp port schema")?;
        if port_chirho.schema_chirho.0 != ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO {
            bail!("AssetOp port does not name the canonical ledger-owned schema");
        }
        if previous_chirho
            .is_some_and(|value_chirho| value_chirho >= port_chirho.port_chirho.as_str())
        {
            bail!("AssetOp ports must be strictly byte-sorted and unique");
        }
        previous_chirho = Some(&port_chirho.port_chirho);
    }
    Ok(())
}

/// Exact-resolves one contract's checked money port against the immutable node definition.
///
/// This is shared by descriptor-v2 deployment verification and runtime effect admission. It is
/// deliberately structural: the contract names the port and ledger-owned schema; app payloads do
/// not get to self-declare either one.
pub fn validate_asset_op_port_binding_chirho(
    contract_chirho: &BlessedReversionContractChirho,
    node_chirho: &NodeDefChirho,
) -> Result<bool> {
    validate_asset_op_ports_chirho(&contract_chirho.asset_op_ports_chirho)?;
    let Some(requirement_chirho) = contract_chirho.asset_op_ports_chirho.first() else {
        return Ok(false);
    };
    let [input_chirho] = node_chirho.inputs_chirho.as_slice() else {
        bail!("descriptor-v2 v1 AssetOp effect node must have exactly one request input");
    };
    if input_chirho.name_chirho != requirement_chirho.port_chirho {
        bail!("AssetOp contract port is absent from the verified effect node");
    }
    if input_chirho.schema_chirho != requirement_chirho.schema_chirho {
        bail!("verified effect node AssetOp port does not name the canonical schema");
    }
    Ok(true)
}

fn validate_selector_chirho(selector_chirho: &EffectDoorSelectorChirho) -> Result<()> {
    if let EffectDoorSelectorChirho::PaidEffectChirho { effect_chirho } = selector_chirho {
        validate_label_chirho(effect_chirho, "paid-effect subtype")?;
    }
    Ok(())
}

fn selector_is_structural_observation_chirho(selector_chirho: &EffectDoorSelectorChirho) -> bool {
    matches!(
        selector_chirho,
        EffectDoorSelectorChirho::ClockChirho
            | EffectDoorSelectorChirho::RandomChirho
            | EffectDoorSelectorChirho::ReadStoreChirho
            | EffectDoorSelectorChirho::SecretRefChirho
    )
}

fn validate_canonical_capability_multiset_chirho(
    capabilities_chirho: &[CanonicalCapabilityChirho],
) -> Result<()> {
    let mut previous_chirho: Option<&CanonicalCapabilityChirho> = None;
    for capability_chirho in capabilities_chirho {
        validate_canonical_capability_chirho(capability_chirho)?;
        if previous_chirho.is_some_and(|value_chirho| value_chirho >= capability_chirho) {
            bail!("capability multiset must be strictly sorted with no exact duplicates");
        }
        previous_chirho = Some(capability_chirho);
    }
    Ok(())
}

fn validate_canonical_capability_chirho(
    capability_chirho: &CanonicalCapabilityChirho,
) -> Result<()> {
    match capability_chirho {
        CanonicalCapabilityChirho::ReadStoreChirho { prefix_chirho }
        | CanonicalCapabilityChirho::WriteStoreChirho { prefix_chirho } => {
            validate_nonempty_bounded_chirho(prefix_chirho, "store prefix")
        }
        CanonicalCapabilityChirho::PaidEffectChirho {
            effect_chirho,
            caller_chirho,
        } => {
            validate_label_chirho(effect_chirho, "paid-effect subtype")?;
            validate_nonempty_bounded_chirho(caller_chirho, "paid-effect caller")
        }
        CanonicalCapabilityChirho::UserIdentityChirho {
            principal_chirho,
            client_id_chirho,
            token_hash_chirho,
        } => {
            validate_nonempty_bounded_chirho(principal_chirho, "identity principal")?;
            validate_nonempty_bounded_chirho(client_id_chirho, "identity client")?;
            validate_nonempty_bounded_chirho(token_hash_chirho, "identity token hash")
        }
        CanonicalCapabilityChirho::AppContextChirho {
            app_chirho,
            owner_principal_chirho,
            price_book_chirho,
            billing_policy_chirho,
        } => {
            validate_nonempty_bounded_chirho(app_chirho, "app context app")?;
            validate_nonempty_bounded_chirho(owner_principal_chirho, "app context owner")?;
            if let Some(hash_chirho) = price_book_chirho {
                validate_hash_chirho(hash_chirho, "app context price book")?;
            }
            if let Some(hash_chirho) = billing_policy_chirho {
                validate_hash_chirho(hash_chirho, "app context billing policy")?;
            }
            Ok(())
        }
        CanonicalCapabilityChirho::SecretRefChirho { name_chirho } => {
            validate_label_chirho(name_chirho, "secret ref")
        }
        CanonicalCapabilityChirho::RealtimeSessionChirho {
            app_chirho,
            caller_chirho,
        } => {
            validate_nonempty_bounded_chirho(app_chirho, "realtime app")?;
            validate_nonempty_bounded_chirho(caller_chirho, "realtime caller")
        }
        CanonicalCapabilityChirho::SupportIssueChirho {
            issue_chirho,
            actions_chirho,
        } => {
            validate_nonempty_bounded_chirho(issue_chirho, "support issue")?;
            validate_sorted_strings_chirho(actions_chirho, "support actions")
        }
        CanonicalCapabilityChirho::CausalReversionChirho { branch_chirho } => {
            validate_nonempty_bounded_chirho(branch_chirho, "causal-reversion branch")
        }
        CanonicalCapabilityChirho::NetChirho { allowlist_chirho } => {
            validate_sorted_strings_chirho(allowlist_chirho, "network allowlist")
        }
        CanonicalCapabilityChirho::QueryChirho {
            prefix_chirho,
            caller_chirho,
            max_rows_chirho,
        } => {
            validate_nonempty_bounded_chirho(prefix_chirho, "query prefix")?;
            validate_nonempty_bounded_chirho(caller_chirho, "query caller")?;
            if *max_rows_chirho == 0 {
                bail!("query max rows must be positive");
            }
            Ok(())
        }
        CanonicalCapabilityChirho::InvokeChirho { node_chirho } => {
            validate_hash_chirho(node_chirho, "invoke node")
        }
        CanonicalCapabilityChirho::TemplateAppDeployChirho { template_id_chirho } => {
            validate_nonempty_bounded_chirho(template_id_chirho, "template id")
        }
        CanonicalCapabilityChirho::ClockChirho | CanonicalCapabilityChirho::RandomChirho => Ok(()),
    }
}

fn sorted_strings_chirho(values_chirho: &[String]) -> Result<Vec<String>> {
    let mut sorted_chirho = values_chirho.to_vec();
    sorted_chirho.sort();
    validate_sorted_strings_chirho(&sorted_chirho, "capability string set")?;
    Ok(sorted_chirho)
}

fn validate_sorted_strings_chirho(values_chirho: &[String], label_chirho: &str) -> Result<()> {
    if values_chirho.is_empty() {
        bail!("{label_chirho} must be nonempty");
    }
    let mut previous_chirho: Option<&str> = None;
    for value_chirho in values_chirho {
        validate_nonempty_bounded_chirho(value_chirho, label_chirho)?;
        if previous_chirho.is_some_and(|prior_chirho| prior_chirho >= value_chirho.as_str()) {
            bail!("{label_chirho} must be strictly byte-sorted and unique");
        }
        previous_chirho = Some(value_chirho);
    }
    Ok(())
}

fn validate_sorted_unique_chirho<T: Ord>(
    values_chirho: &[T],
    maximum_chirho: usize,
    label_chirho: &str,
) -> Result<()> {
    if values_chirho.len() > maximum_chirho {
        bail!("{label_chirho} count exceeds its engine bound");
    }
    if values_chirho
        .windows(2)
        .any(|pair_chirho| pair_chirho[0] >= pair_chirho[1])
    {
        bail!("{label_chirho} must be strictly sorted and unique");
    }
    Ok(())
}

fn validate_label_chirho(value_chirho: &str, label_chirho: &str) -> Result<()> {
    validate_nonempty_bounded_chirho(value_chirho, label_chirho)?;
    if !value_chirho.bytes().all(|byte_chirho| {
        byte_chirho.is_ascii_alphanumeric() || matches!(byte_chirho, b'.' | b'_' | b'-' | b':')
    }) {
        bail!("{label_chirho} contains a non-canonical character");
    }
    Ok(())
}

fn validate_nonempty_bounded_chirho(value_chirho: &str, label_chirho: &str) -> Result<()> {
    if value_chirho.is_empty() || value_chirho.len() > MAX_CONTRACT_LABEL_BYTES_CHIRHO {
        bail!("{label_chirho} must be nonempty and bounded");
    }
    Ok(())
}

fn builtin_write_store_contract_chirho() -> BlessedReversionContractChirho {
    BlessedReversionContractChirho {
        schema_chirho: REVERSION_CONTRACT_SCHEMA_CHIRHO.to_string(),
        contract_key_chirho: BlessedContractKeyChirho("write-store-chirho".to_string()),
        effect_selector_chirho: EffectDoorSelectorChirho::WriteStoreChirho,
        supporting_requirements_chirho: Vec::new(),
        produced_evidence_chirho: vec![
            UndoEvidenceKindChirho::EffectIdempotencyKeyChirho,
            UndoEvidenceKindChirho::RequestRefChirho,
            UndoEvidenceKindChirho::ResponseRefChirho,
            UndoEvidenceKindChirho::BeforeImageRefChirho,
            UndoEvidenceKindChirho::PostStateFingerprintChirho,
            UndoEvidenceKindChirho::PreviousHeadRefChirho,
            UndoEvidenceKindChirho::SubjectRefChirho,
        ],
        disposition_chirho: UndoDispositionChirho::CompensableChirho {
            steps_chirho: vec![UndoStepTemplateChirho {
                action_chirho: UndoActionChirho::ConditionalRestoreChirho,
                required_evidence_chirho: vec![
                    UndoEvidenceKindChirho::EffectIdempotencyKeyChirho,
                    UndoEvidenceKindChirho::BeforeImageRefChirho,
                    UndoEvidenceKindChirho::PostStateFingerprintChirho,
                ],
                verification_chirho: UndoVerificationModeChirho::VerifyPostFingerprintChirho,
            }],
            residuals_chirho: Vec::new(),
            admission_gate_chirho: None,
        },
        privacy_floor_chirho: PrivacyClassChirho::DirectChirho,
        max_depth_chirho: 8,
        config_ports_chirho: Vec::new(),
        asset_op_ports_chirho: Vec::new(),
        reconciliation_requirement_chirho: None,
        pricing_source_requirement_chirho: None,
        effect_result_cache_posture_chirho: None,
    }
}

fn builtin_read_store_contract_chirho() -> BlessedReversionContractChirho {
    BlessedReversionContractChirho {
        schema_chirho: REVERSION_CONTRACT_SCHEMA_CHIRHO.to_string(),
        contract_key_chirho: BlessedContractKeyChirho("read-store-chirho".to_string()),
        effect_selector_chirho: EffectDoorSelectorChirho::ReadStoreChirho,
        supporting_requirements_chirho: Vec::new(),
        produced_evidence_chirho: vec![
            UndoEvidenceKindChirho::EffectIdempotencyKeyChirho,
            UndoEvidenceKindChirho::RequestRefChirho,
            UndoEvidenceKindChirho::ResponseRefChirho,
        ],
        disposition_chirho: UndoDispositionChirho::ObservationOnlyChirho {
            reason_code_chirho: ObservationReasonChirho::ReadOnlyCapabilityChirho,
        },
        privacy_floor_chirho: PrivacyClassChirho::DirectChirho,
        max_depth_chirho: 8,
        config_ports_chirho: Vec::new(),
        asset_op_ports_chirho: Vec::new(),
        reconciliation_requirement_chirho: None,
        pricing_source_requirement_chirho: None,
        effect_result_cache_posture_chirho: Some(
            EffectResultCachePostureChirho::NeverReuseEffectResultChirho,
        ),
    }
}

fn builtin_query_contract_chirho() -> BlessedReversionContractChirho {
    caller_residual_contract_chirho(
        "query-chirho",
        EffectDoorSelectorChirho::QueryChirho,
        vec![SupportingCapabilityRequirementChirho::QueryCallerIdentityChirho],
        IrreversibleResidualChirho::CallerExposureChirho,
        "query-admission-gate-chirho",
    )
}

fn builtin_llm_contract_chirho() -> BlessedReversionContractChirho {
    let mut contract_chirho = caller_residual_contract_chirho(
        "llm-chirho",
        EffectDoorSelectorChirho::PaidEffectChirho {
            effect_chirho: LLM_SERVED_EFFECT_SUBTYPE_CHIRHO.to_string(),
        },
        Vec::new(),
        IrreversibleResidualChirho::ProviderWorkConsumedChirho,
        "llm-admission-gate-chirho",
    );
    // The served LLM money ladder (`llm_served_chirho.rs`) checks these three the same way
    // `run_postgres_reversible_chirho` does, so the signed contract must carry them, and each is a
    // money-authority invariant rather than a subtype inference:
    // - VerifiedPriceBook: the price is the operator's signed price-book row, never caller-selected.
    // - NeverReuse: an LLM retry must REACH the ladder (not short-circuit via the generic effect
    //   log), so it is deduped and metered at the ledger, never silently served free.
    // - QueryByEffectKey: an in-doubt Hold is resolved only by the provider's read-by-exact-K.
    // Setting them here (not in the shared `caller_residual_contract_chirho`) keeps every other
    // caller-residual contract byte-identical. It DOES change this contract's bytes and therefore
    // the whole-set contract-set digest, so authoring fixtures rebuild.
    contract_chirho.reconciliation_requirement_chirho =
        Some(EffectReconciliationRequirementChirho::QueryByEffectKeyChirho);
    contract_chirho.pricing_source_requirement_chirho =
        Some(EffectPricingSourceRequirementChirho::VerifiedPriceBookChirho);
    contract_chirho.effect_result_cache_posture_chirho =
        Some(EffectResultCachePostureChirho::NeverReuseEffectResultChirho);
    contract_chirho
}

fn builtin_postgres_reversible_contract_chirho() -> BlessedReversionContractChirho {
    BlessedReversionContractChirho {
        schema_chirho: REVERSION_CONTRACT_SCHEMA_CHIRHO.to_string(),
        contract_key_chirho: BlessedContractKeyChirho("postgres-reversible-chirho".to_string()),
        effect_selector_chirho: EffectDoorSelectorChirho::PaidEffectChirho {
            effect_chirho: POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO.to_string(),
        },
        supporting_requirements_chirho: Vec::new(),
        produced_evidence_chirho: vec![
            UndoEvidenceKindChirho::EffectIdempotencyKeyChirho,
            UndoEvidenceKindChirho::RequestRefChirho,
            UndoEvidenceKindChirho::ResponseRefChirho,
            UndoEvidenceKindChirho::BeforeImageRefChirho,
            UndoEvidenceKindChirho::PostStateFingerprintChirho,
            UndoEvidenceKindChirho::ProviderReceiptRefChirho,
            UndoEvidenceKindChirho::AuthorityEvidenceRefChirho,
            UndoEvidenceKindChirho::SubjectRefChirho,
        ],
        disposition_chirho: UndoDispositionChirho::CompensableChirho {
            steps_chirho: vec![UndoStepTemplateChirho {
                action_chirho: UndoActionChirho::ConditionalRestoreChirho,
                required_evidence_chirho: vec![
                    UndoEvidenceKindChirho::EffectIdempotencyKeyChirho,
                    UndoEvidenceKindChirho::BeforeImageRefChirho,
                    UndoEvidenceKindChirho::PostStateFingerprintChirho,
                    UndoEvidenceKindChirho::ProviderReceiptRefChirho,
                ],
                verification_chirho: UndoVerificationModeChirho::VerifyPostFingerprintChirho,
            }],
            residuals_chirho: vec![IrreversibleResidualChirho::ForwardOnlyAuthorityRecordChirho],
            admission_gate_chirho: Some(stable_ref_chirho(
                "postgres-reversible-admission-gate-chirho",
            )),
        },
        privacy_floor_chirho: PrivacyClassChirho::DirectChirho,
        max_depth_chirho: 8,
        config_ports_chirho: Vec::new(),
        asset_op_ports_chirho: Vec::new(),
        reconciliation_requirement_chirho: Some(
            EffectReconciliationRequirementChirho::QueryByEffectKeyChirho,
        ),
        pricing_source_requirement_chirho: Some(
            EffectPricingSourceRequirementChirho::VerifiedPriceBookChirho,
        ),
        effect_result_cache_posture_chirho: Some(
            EffectResultCachePostureChirho::NeverReuseEffectResultChirho,
        ),
    }
}

fn caller_residual_contract_chirho(
    key_chirho: &str,
    selector_chirho: EffectDoorSelectorChirho,
    supporting_chirho: Vec<SupportingCapabilityRequirementChirho>,
    residual_chirho: IrreversibleResidualChirho,
    gate_label_chirho: &str,
) -> BlessedReversionContractChirho {
    BlessedReversionContractChirho {
        schema_chirho: REVERSION_CONTRACT_SCHEMA_CHIRHO.to_string(),
        contract_key_chirho: BlessedContractKeyChirho(key_chirho.to_string()),
        effect_selector_chirho: selector_chirho,
        supporting_requirements_chirho: supporting_chirho,
        produced_evidence_chirho: vec![
            UndoEvidenceKindChirho::EffectIdempotencyKeyChirho,
            UndoEvidenceKindChirho::RequestRefChirho,
            UndoEvidenceKindChirho::ResponseRefChirho,
            UndoEvidenceKindChirho::ProviderReceiptRefChirho,
            UndoEvidenceKindChirho::AuthorityEvidenceRefChirho,
            UndoEvidenceKindChirho::SubjectRefChirho,
        ],
        disposition_chirho: UndoDispositionChirho::CompensableChirho {
            steps_chirho: vec![UndoStepTemplateChirho {
                action_chirho: UndoActionChirho::CorrectiveForwardChirho,
                required_evidence_chirho: vec![
                    UndoEvidenceKindChirho::EffectIdempotencyKeyChirho,
                    UndoEvidenceKindChirho::ProviderReceiptRefChirho,
                ],
                verification_chirho: UndoVerificationModeChirho::VerifyProviderReceiptChirho,
            }],
            residuals_chirho: vec![residual_chirho],
            admission_gate_chirho: Some(stable_ref_chirho(gate_label_chirho)),
        },
        privacy_floor_chirho: PrivacyClassChirho::DirectChirho,
        max_depth_chirho: 8,
        config_ports_chirho: Vec::new(),
        asset_op_ports_chirho: Vec::new(),
        reconciliation_requirement_chirho: None,
        pricing_source_requirement_chirho: None,
        effect_result_cache_posture_chirho: None,
    }
}

fn builtin_template_deploy_contract_chirho() -> BlessedReversionContractChirho {
    BlessedReversionContractChirho {
        schema_chirho: REVERSION_CONTRACT_SCHEMA_CHIRHO.to_string(),
        contract_key_chirho: BlessedContractKeyChirho("template-app-deploy-chirho".to_string()),
        effect_selector_chirho: EffectDoorSelectorChirho::TemplateAppDeployChirho,
        supporting_requirements_chirho: Vec::new(),
        produced_evidence_chirho: vec![
            UndoEvidenceKindChirho::EffectIdempotencyKeyChirho,
            UndoEvidenceKindChirho::RequestRefChirho,
            UndoEvidenceKindChirho::ResponseRefChirho,
            UndoEvidenceKindChirho::PostStateFingerprintChirho,
            UndoEvidenceKindChirho::PreviousHeadRefChirho,
            UndoEvidenceKindChirho::AuthorityEvidenceRefChirho,
        ],
        disposition_chirho: UndoDispositionChirho::CompensableChirho {
            steps_chirho: vec![UndoStepTemplateChirho {
                action_chirho: UndoActionChirho::ConditionalRestoreChirho,
                required_evidence_chirho: vec![
                    UndoEvidenceKindChirho::EffectIdempotencyKeyChirho,
                    UndoEvidenceKindChirho::PostStateFingerprintChirho,
                    UndoEvidenceKindChirho::PreviousHeadRefChirho,
                ],
                verification_chirho: UndoVerificationModeChirho::VerifyPostFingerprintChirho,
            }],
            residuals_chirho: vec![
                IrreversibleResidualChirho::PublishedUrlObservedChirho,
                IrreversibleResidualChirho::ForwardOnlyAuthorityRecordChirho,
            ],
            admission_gate_chirho: Some(stable_ref_chirho("template-deploy-gate-chirho")),
        },
        privacy_floor_chirho: PrivacyClassChirho::DirectChirho,
        max_depth_chirho: 8,
        config_ports_chirho: Vec::new(),
        asset_op_ports_chirho: Vec::new(),
        reconciliation_requirement_chirho: None,
        pricing_source_requirement_chirho: None,
        effect_result_cache_posture_chirho: None,
    }
}

fn stable_ref_chirho(label_chirho: &str) -> HashChirho {
    HashChirho(blake3::hash(label_chirho.as_bytes()).to_hex().to_string())
}
