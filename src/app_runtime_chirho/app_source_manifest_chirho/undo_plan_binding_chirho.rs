// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Authority-inert CAS binding and exact verification for candidate static undo plans.

use super::{
    validate_app_source_candidate_report_schema_chirho, AppSourceCandidateReportChirho,
    AppSourceUndoPlanBindingChirho,
};
use crate::blessed_chirho::{
    registry_v2_message_from_contract_set_chirho, validate_registry_v2_node_effects_chirho,
    BlessedRegistryV2MessageChirho,
};
use crate::model_chirho::{DagChirho, HashChirho, NodeDefChirho};
use crate::{cas_chirho, store_chirho};
use anyhow::{bail, Context, Result};
use cairn_undo_plan_chirho::canonical_chirho::{
    canonical_undo_plan_bytes_chirho, contract_set_digest_chirho, parse_canonical_undo_plan_chirho,
    undo_plan_hash_chirho,
};
use cairn_undo_plan_chirho::contract_chirho::{
    canonical_authoring_reversion_contract_set_chirho, BlessedReversionContractSetChirho,
    CanonicalCapabilityChirho, IrreversibleResidualChirho, ObservationReasonChirho,
    UndoActionChirho, UndoDispositionChirho, UndoEvidenceKindChirho, UndoVerificationModeChirho,
};
use cairn_undo_plan_chirho::derive_chirho::{derive_undo_plan_chirho, VerifiedUndoDagInputChirho};
use cairn_undo_plan_chirho::plan_chirho::{
    UndoDoorKeyChirho, UndoPlanChirho, UndoPlanEffectDoorChirho,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Redacted, non-authoritative review view of one exact verified DAG undo plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAppSourceUndoPlanReviewChirho {
    pub dag_chirho: HashChirho,
    pub plan_cas_chirho: HashChirho,
    pub plan_digest_chirho: HashChirho,
    pub contract_set_digest_chirho: HashChirho,
    pub effect_count_chirho: usize,
    pub max_depth_chirho: u16,
    pub doors_chirho: Vec<VerifiedAppSourceUndoDoorReviewChirho>,
}

/// Redacted review semantics for one effect door. Capability payload values are deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAppSourceUndoDoorReviewChirho {
    pub position_chirho: usize,
    pub contract_chirho: String,
    pub effect_kind_chirho: String,
    pub supporting_kinds_chirho: Vec<String>,
    pub depends_on_positions_chirho: Vec<usize>,
    pub produced_evidence_chirho: Vec<String>,
    pub disposition_chirho: String,
    pub steps_chirho: Vec<VerifiedAppSourceUndoStepReviewChirho>,
    pub residuals_chirho: Vec<String>,
    pub admission_gate_required_chirho: bool,
    pub remediation_required_chirho: bool,
    pub privacy_class_chirho: String,
    pub config_ports_chirho: Vec<String>,
}

/// Redacted review semantics for one ordered compensation step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAppSourceUndoStepReviewChirho {
    pub action_chirho: String,
    pub required_evidence_chirho: Vec<String>,
    pub verification_chirho: String,
}

struct VerifiedDescriptorV2PlanBindingChirho<'a> {
    binding_chirho: &'a AppSourceUndoPlanBindingChirho,
    plan_chirho: UndoPlanChirho,
}

/// Full exact plan authority retained inside the root crate. Human review callers receive only the
/// redacted DTO above; compensation composition consumes this type through an opaque token.
pub(crate) struct VerifiedAppSourceUndoPlanChirho {
    pub(crate) binding_chirho: AppSourceUndoPlanBindingChirho,
    pub(crate) plan_chirho: UndoPlanChirho,
}

fn descriptor_v2_authority_chirho() -> Result<(
    BlessedReversionContractSetChirho,
    BlessedRegistryV2MessageChirho,
    HashChirho,
)> {
    let contract_set_chirho = canonical_authoring_reversion_contract_set_chirho();
    let contract_set_digest_chirho = contract_set_digest_chirho(&contract_set_chirho)?;
    let registry_message_chirho =
        registry_v2_message_from_contract_set_chirho(&contract_set_chirho)?;
    Ok((
        contract_set_chirho,
        registry_message_chirho,
        contract_set_digest_chirho,
    ))
}

/// Mints prospective descriptor-v2 identity as documented in
/// `spec-chirho/workflows-chirho/undo-chirho/static-undo-plan-design-chirho.md` section 4.2.1.
pub(super) fn bind_new_descriptor_v2_node_chirho(node_chirho: &mut NodeDefChirho) -> Result<()> {
    if node_chirho.capabilities_chirho.is_empty() {
        node_chirho.effect_contract_set_chirho = None;
        return Ok(());
    }
    let (contract_set_chirho, registry_message_chirho, contract_set_digest_chirho) =
        descriptor_v2_authority_chirho()?;
    node_chirho.effect_contract_set_chirho = Some(contract_set_digest_chirho.clone());
    validate_descriptor_v2_node_with_authority_chirho(
        node_chirho,
        &contract_set_chirho,
        &registry_message_chirho,
        &contract_set_digest_chirho,
    )
}

/// Rechecks the descriptor-v2 node/set binding at every candidate authority boundary.
/// Workflow: `spec-chirho/workflows-chirho/undo-chirho/static-undo-plan-design-chirho.md` 4.2.1.
pub(super) fn validate_descriptor_v2_node_chirho(node_chirho: &NodeDefChirho) -> Result<()> {
    let (contract_set_chirho, registry_message_chirho, contract_set_digest_chirho) =
        descriptor_v2_authority_chirho()?;
    validate_descriptor_v2_node_with_authority_chirho(
        node_chirho,
        &contract_set_chirho,
        &registry_message_chirho,
        &contract_set_digest_chirho,
    )
}

pub(super) fn validate_descriptor_v2_node_with_authority_chirho(
    node_chirho: &NodeDefChirho,
    contract_set_chirho: &BlessedReversionContractSetChirho,
    registry_message_chirho: &BlessedRegistryV2MessageChirho,
    contract_set_digest_chirho: &HashChirho,
) -> Result<()> {
    if node_chirho.capabilities_chirho.is_empty() {
        if node_chirho.effect_contract_set_chirho.is_some() {
            bail!("pure descriptor-v2 node must not name an effect contract set");
        }
        return Ok(());
    }
    if node_chirho.effect_contract_set_chirho.as_ref() != Some(contract_set_digest_chirho) {
        bail!("effectful descriptor-v2 node does not name the current verified contract set");
    }
    validate_registry_v2_node_effects_chirho(
        registry_message_chirho,
        contract_set_chirho,
        node_chirho,
    )
}

fn derive_descriptor_v2_undo_plan_chirho(
    input_chirho: &VerifiedUndoDagInputChirho,
    contract_set_chirho: &BlessedReversionContractSetChirho,
    registry_message_chirho: &BlessedRegistryV2MessageChirho,
    contract_set_digest_chirho: &HashChirho,
) -> Result<UndoPlanChirho> {
    for node_chirho in input_chirho.node_defs_chirho.values() {
        validate_descriptor_v2_node_with_authority_chirho(
            node_chirho,
            contract_set_chirho,
            registry_message_chirho,
            contract_set_digest_chirho,
        )?;
    }
    let plan_chirho = derive_undo_plan_chirho(input_chirho, contract_set_chirho)?;
    if plan_chirho.contract_set_digest_chirho != *contract_set_digest_chirho {
        bail!("derived undo plan does not bind the current verified contract set");
    }
    Ok(plan_chirho)
}

pub(super) fn validate_descriptor_v2_executable_dags_chirho(
    root_chirho: &Path,
    executable_dags_chirho: &BTreeSet<HashChirho>,
) -> Result<()> {
    if executable_dags_chirho.is_empty() {
        bail!("descriptor-v2 action has no executable DAG");
    }
    let (contract_set_chirho, registry_message_chirho, contract_set_digest_chirho) =
        descriptor_v2_authority_chirho()?;
    for dag_hash_chirho in executable_dags_chirho {
        let input_chirho = load_verified_undo_input_chirho(root_chirho, dag_hash_chirho)?;
        derive_descriptor_v2_undo_plan_chirho(
            &input_chirho,
            &contract_set_chirho,
            &registry_message_chirho,
            &contract_set_digest_chirho,
        )?;
    }
    Ok(())
}

/// Enforces the descriptor-v2 deployment boundary documented in
/// `spec-chirho/workflows-chirho/undo-chirho/static-undo-plan-design-chirho.md` section 4.2.1.
pub(crate) fn verify_descriptor_v2_deployment_chirho(
    root_chirho: &Path,
    executable_dags_chirho: &BTreeSet<HashChirho>,
    bindings_chirho: Option<&[AppSourceUndoPlanBindingChirho]>,
) -> Result<()> {
    let Some(bindings_chirho) = bindings_chirho else {
        for dag_hash_chirho in executable_dags_chirho {
            let input_chirho = load_verified_undo_input_chirho(root_chirho, dag_hash_chirho)?;
            for node_chirho in input_chirho.node_defs_chirho.values() {
                if !node_chirho.capabilities_chirho.is_empty() {
                    bail!(
                        "effectful descriptor-v2 deployment requires complete verified undo-plan bindings"
                    );
                }
                validate_descriptor_v2_node_chirho(node_chirho)?;
            }
        }
        return Ok(());
    };

    verify_descriptor_v2_plan_bindings_for_dags_chirho(
        root_chirho,
        executable_dags_chirho,
        bindings_chirho,
    )
    .map(drop)
}

/// Implements the candidate/review portion of the static-undo workflow documented in
/// `spec-chirho/workflows-chirho/undo-chirho/static-undo-plan-design-chirho.md`.
pub(super) fn derive_and_store_app_source_undo_plan_bindings_chirho(
    root_chirho: &Path,
    executable_dags_chirho: &BTreeSet<HashChirho>,
) -> Result<Vec<AppSourceUndoPlanBindingChirho>> {
    if executable_dags_chirho.is_empty() {
        bail!("app source candidate has no executable DAG for undo-plan derivation");
    }
    let (contract_set_chirho, registry_message_chirho, expected_contract_set_digest_chirho) =
        descriptor_v2_authority_chirho()?;
    executable_dags_chirho
        .iter()
        .map(|dag_hash_chirho| {
            let input_chirho = load_verified_undo_input_chirho(root_chirho, dag_hash_chirho)?;
            let plan_chirho = derive_descriptor_v2_undo_plan_chirho(
                &input_chirho,
                &contract_set_chirho,
                &registry_message_chirho,
                &expected_contract_set_digest_chirho,
            )?;
            let plan_bytes_chirho = canonical_undo_plan_bytes_chirho(&plan_chirho)?;
            let plan_cas_chirho = cas_chirho::add_chirho(root_chirho, &plan_bytes_chirho)?;
            Ok(AppSourceUndoPlanBindingChirho {
                dag_chirho: dag_hash_chirho.clone(),
                plan_cas_chirho,
                plan_digest_chirho: undo_plan_hash_chirho(&plan_chirho)?,
                contract_set_digest_chirho: plan_chirho.contract_set_digest_chirho,
            })
        })
        .collect()
}

pub(super) fn verify_app_source_undo_plan_bindings_chirho(
    root_chirho: &Path,
    candidate_chirho: &AppSourceCandidateReportChirho,
) -> Result<()> {
    load_verified_app_source_undo_plan_reviews_chirho(root_chirho, candidate_chirho).map(drop)
}

pub(super) fn verify_new_app_source_candidate_descriptor_v2_chirho(
    root_chirho: &Path,
    candidate_chirho: &AppSourceCandidateReportChirho,
) -> Result<()> {
    validate_app_source_candidate_report_schema_chirho(candidate_chirho)?;
    if candidate_chirho
        .undo_plan_bindings_chirho
        .as_ref()
        .is_none_or(Vec::is_empty)
    {
        bail!("new descriptor-v2 candidate requires complete undo-plan bindings");
    }
    validate_descriptor_v2_executable_dags_chirho(
        root_chirho,
        &executable_dag_hashes_chirho(candidate_chirho),
    )?;
    verify_app_source_undo_plan_bindings_chirho(root_chirho, candidate_chirho)
}

/// Reloads, verifies, and redacts every root/route plan for human review display.
///
/// The returned DTO carries review semantics only. It is not a compensation authority token and
/// omits capability payload values such as principals, scopes, and token hashes.
pub fn load_verified_app_source_undo_plan_reviews_chirho(
    root_chirho: &Path,
    candidate_chirho: &AppSourceCandidateReportChirho,
) -> Result<Vec<VerifiedAppSourceUndoPlanReviewChirho>> {
    load_verified_app_source_undo_plans_chirho(root_chirho, candidate_chirho)?
        .iter()
        .map(|verified_chirho| {
            review_surface_chirho(
                &verified_chirho.binding_chirho,
                &verified_chirho.plan_chirho,
            )
        })
        .collect()
}

pub(crate) fn load_verified_app_source_undo_plans_chirho(
    root_chirho: &Path,
    candidate_chirho: &AppSourceCandidateReportChirho,
) -> Result<Vec<VerifiedAppSourceUndoPlanChirho>> {
    validate_app_source_candidate_report_schema_chirho(candidate_chirho)?;
    let Some(bindings_chirho) = &candidate_chirho.undo_plan_bindings_chirho else {
        // Pre-v2 reports remain readable; new effectful deployment requires v2 bindings.
        return Ok(Vec::new());
    };
    if bindings_chirho.is_empty() {
        bail!("plan-bearing app source candidate has no undo-plan bindings");
    }

    let expected_dags_chirho = executable_dag_hashes_chirho(candidate_chirho);
    verify_descriptor_v2_plan_bindings_for_dags_chirho(
        root_chirho,
        &expected_dags_chirho,
        bindings_chirho,
    )?
    .into_iter()
    .map(|verified_chirho| {
        Ok(VerifiedAppSourceUndoPlanChirho {
            binding_chirho: verified_chirho.binding_chirho.clone(),
            plan_chirho: verified_chirho.plan_chirho,
        })
    })
    .collect()
}

fn verify_descriptor_v2_plan_bindings_for_dags_chirho<'a>(
    root_chirho: &Path,
    expected_dags_chirho: &BTreeSet<HashChirho>,
    bindings_chirho: &'a [AppSourceUndoPlanBindingChirho],
) -> Result<Vec<VerifiedDescriptorV2PlanBindingChirho<'a>>> {
    if bindings_chirho.is_empty() {
        bail!("descriptor-v2 deployment has an empty undo-plan binding list");
    }
    if bindings_chirho
        .windows(2)
        .any(|pair_chirho| pair_chirho[0].dag_chirho >= pair_chirho[1].dag_chirho)
    {
        bail!("descriptor-v2 undo-plan bindings must be strictly sorted by unique DAG hash");
    }
    let bound_dags_chirho = bindings_chirho
        .iter()
        .map(|binding_chirho| binding_chirho.dag_chirho.clone())
        .collect::<BTreeSet<_>>();
    if bound_dags_chirho.len() != bindings_chirho.len() {
        bail!("app source candidate repeats an undo-plan DAG binding");
    }
    if &bound_dags_chirho != expected_dags_chirho {
        bail!("app source candidate undo-plan bindings do not exactly cover root plus route DAGs");
    }

    let contract_set_chirho = canonical_authoring_reversion_contract_set_chirho();
    let expected_contract_set_digest_chirho = contract_set_digest_chirho(&contract_set_chirho)?;
    let registry_message_chirho =
        registry_v2_message_from_contract_set_chirho(&contract_set_chirho)?;
    let mut verified_chirho = Vec::with_capacity(bindings_chirho.len());
    for binding_chirho in bindings_chirho {
        if binding_chirho.contract_set_digest_chirho != expected_contract_set_digest_chirho {
            bail!("app source candidate mixes or drifts undo-plan contract sets");
        }
        let plan_bytes_chirho =
            cas_chirho::get_chirho(root_chirho, &binding_chirho.plan_cas_chirho)
                .context("load candidate undo-plan CAS artifact")?;
        let plan_text_chirho = std::str::from_utf8(&plan_bytes_chirho)
            .context("candidate undo-plan artifact is not UTF-8")?;
        let plan_chirho = parse_canonical_undo_plan_chirho(plan_text_chirho)?;
        if plan_chirho.source_dag_chirho != binding_chirho.dag_chirho {
            bail!("candidate undo-plan source DAG differs from its binding");
        }
        if plan_chirho.contract_set_digest_chirho != binding_chirho.contract_set_digest_chirho {
            bail!("candidate undo-plan contract-set digest differs from its binding");
        }
        if undo_plan_hash_chirho(&plan_chirho)? != binding_chirho.plan_digest_chirho {
            bail!("candidate undo-plan domain digest differs from its binding");
        }

        let input_chirho =
            load_verified_undo_input_chirho(root_chirho, &binding_chirho.dag_chirho)?;
        let rederived_chirho = derive_descriptor_v2_undo_plan_chirho(
            &input_chirho,
            &contract_set_chirho,
            &registry_message_chirho,
            &expected_contract_set_digest_chirho,
        )?;
        let rederived_bytes_chirho = canonical_undo_plan_bytes_chirho(&rederived_chirho)?;
        if rederived_bytes_chirho != plan_bytes_chirho {
            bail!("candidate undo-plan bytes differ from exact re-derivation");
        }
        verified_chirho.push(VerifiedDescriptorV2PlanBindingChirho {
            binding_chirho,
            plan_chirho,
        });
    }
    Ok(verified_chirho)
}

fn review_surface_chirho(
    binding_chirho: &AppSourceUndoPlanBindingChirho,
    plan_chirho: &UndoPlanChirho,
) -> Result<VerifiedAppSourceUndoPlanReviewChirho> {
    let positions_chirho = plan_chirho
        .effect_doors_chirho
        .iter()
        .enumerate()
        .map(|(index_chirho, door_chirho)| (door_chirho.door_chirho.clone(), index_chirho + 1))
        .collect::<BTreeMap<UndoDoorKeyChirho, usize>>();
    let doors_chirho = plan_chirho
        .effect_doors_chirho
        .iter()
        .enumerate()
        .map(|(index_chirho, door_chirho)| {
            review_door_surface_chirho(index_chirho + 1, door_chirho, &positions_chirho)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(VerifiedAppSourceUndoPlanReviewChirho {
        dag_chirho: binding_chirho.dag_chirho.clone(),
        plan_cas_chirho: binding_chirho.plan_cas_chirho.clone(),
        plan_digest_chirho: binding_chirho.plan_digest_chirho.clone(),
        contract_set_digest_chirho: binding_chirho.contract_set_digest_chirho.clone(),
        effect_count_chirho: doors_chirho.len(),
        max_depth_chirho: plan_chirho.max_depth_chirho,
        doors_chirho,
    })
}

fn review_door_surface_chirho(
    position_chirho: usize,
    door_chirho: &UndoPlanEffectDoorChirho,
    positions_chirho: &BTreeMap<UndoDoorKeyChirho, usize>,
) -> Result<VerifiedAppSourceUndoDoorReviewChirho> {
    let depends_on_positions_chirho = door_chirho
        .depends_on_doors_chirho
        .iter()
        .map(|key_chirho| {
            positions_chirho
                .get(key_chirho)
                .copied()
                .context("verified undo-plan dependency is absent from review view")
        })
        .collect::<Result<Vec<_>>>()?;
    let (
        disposition_chirho,
        steps_chirho,
        residuals_chirho,
        admission_gate_required_chirho,
        remediation_required_chirho,
    ) = disposition_review_chirho(&door_chirho.contract_chirho.disposition_chirho);
    let privacy_class_chirho =
        serde_json::to_value(door_chirho.contract_chirho.privacy_floor_chirho)
            .context("encode verified undo-plan privacy class for review")?
            .as_str()
            .context("verified undo-plan privacy class is not a wire label")?
            .to_string();
    Ok(VerifiedAppSourceUndoDoorReviewChirho {
        position_chirho,
        contract_chirho: door_chirho.contract_chirho.contract_key_chirho.0.clone(),
        effect_kind_chirho: capability_kind_chirho(&door_chirho.effect_capability_chirho).into(),
        supporting_kinds_chirho: door_chirho
            .supporting_capabilities_chirho
            .iter()
            .map(|capability_chirho| capability_kind_chirho(capability_chirho).to_string())
            .collect(),
        depends_on_positions_chirho,
        produced_evidence_chirho: door_chirho
            .contract_chirho
            .produced_evidence_chirho
            .iter()
            .map(|evidence_chirho| evidence_kind_chirho(evidence_chirho).to_string())
            .collect(),
        disposition_chirho,
        steps_chirho,
        residuals_chirho,
        admission_gate_required_chirho,
        remediation_required_chirho,
        privacy_class_chirho,
        config_ports_chirho: door_chirho
            .config_refs_chirho
            .iter()
            .map(|reference_chirho| reference_chirho.port_chirho.clone())
            .collect(),
    })
}

fn disposition_review_chirho(
    disposition_chirho: &UndoDispositionChirho,
) -> (
    String,
    Vec<VerifiedAppSourceUndoStepReviewChirho>,
    Vec<String>,
    bool,
    bool,
) {
    match disposition_chirho {
        UndoDispositionChirho::ObservationOnlyChirho { reason_code_chirho } => (
            format!(
                "observation-only-chirho/{}",
                observation_reason_chirho(reason_code_chirho)
            ),
            Vec::new(),
            Vec::new(),
            false,
            false,
        ),
        UndoDispositionChirho::CompensableChirho {
            steps_chirho,
            residuals_chirho,
            admission_gate_chirho,
        } => (
            "compensable-chirho".into(),
            steps_chirho
                .iter()
                .map(|step_chirho| VerifiedAppSourceUndoStepReviewChirho {
                    action_chirho: action_kind_chirho(&step_chirho.action_chirho).into(),
                    required_evidence_chirho: step_chirho
                        .required_evidence_chirho
                        .iter()
                        .map(|evidence_chirho| evidence_kind_chirho(evidence_chirho).to_string())
                        .collect(),
                    verification_chirho: verification_kind_chirho(&step_chirho.verification_chirho)
                        .into(),
                })
                .collect(),
            residuals_chirho
                .iter()
                .map(|residual_chirho| residual_kind_chirho(residual_chirho).to_string())
                .collect(),
            admission_gate_chirho.is_some(),
            false,
        ),
        UndoDispositionChirho::IrreversibleGatedChirho {
            residuals_chirho, ..
        } => (
            "irreversible-gated-chirho".into(),
            Vec::new(),
            residuals_chirho
                .iter()
                .map(|residual_chirho| residual_kind_chirho(residual_chirho).to_string())
                .collect(),
            true,
            true,
        ),
    }
}

fn capability_kind_chirho(capability_chirho: &CanonicalCapabilityChirho) -> &'static str {
    match capability_chirho {
        CanonicalCapabilityChirho::ReadStoreChirho { .. } => "read-store-chirho",
        CanonicalCapabilityChirho::WriteStoreChirho { .. } => "write-store-chirho",
        CanonicalCapabilityChirho::PaidEffectChirho { .. } => "paid-effect-chirho",
        CanonicalCapabilityChirho::UserIdentityChirho { .. } => "user-identity-chirho",
        CanonicalCapabilityChirho::AppContextChirho { .. } => "app-context-chirho",
        CanonicalCapabilityChirho::SecretRefChirho { .. } => "secret-ref-chirho",
        CanonicalCapabilityChirho::RealtimeSessionChirho { .. } => "realtime-session-chirho",
        CanonicalCapabilityChirho::SupportIssueChirho { .. } => "support-issue-chirho",
        CanonicalCapabilityChirho::CausalReversionChirho { .. } => "causal-reversion-chirho",
        CanonicalCapabilityChirho::NetChirho { .. } => "net-chirho",
        CanonicalCapabilityChirho::QueryChirho { .. } => "query-chirho",
        CanonicalCapabilityChirho::ClockChirho => "clock-chirho",
        CanonicalCapabilityChirho::RandomChirho => "random-chirho",
        CanonicalCapabilityChirho::InvokeChirho { .. } => "invoke-chirho",
        CanonicalCapabilityChirho::TemplateAppDeployChirho { .. } => "template-app-deploy-chirho",
    }
}

fn evidence_kind_chirho(evidence_chirho: &UndoEvidenceKindChirho) -> &'static str {
    match evidence_chirho {
        UndoEvidenceKindChirho::EffectIdempotencyKeyChirho => "effect-idempotency-key-chirho",
        UndoEvidenceKindChirho::RequestRefChirho => "request-ref-chirho",
        UndoEvidenceKindChirho::ResponseRefChirho => "response-ref-chirho",
        UndoEvidenceKindChirho::BeforeImageRefChirho => "before-image-ref-chirho",
        UndoEvidenceKindChirho::PostStateFingerprintChirho => "post-state-fingerprint-chirho",
        UndoEvidenceKindChirho::PreviousHeadRefChirho => "previous-head-ref-chirho",
        UndoEvidenceKindChirho::ProviderReceiptRefChirho => "provider-receipt-ref-chirho",
        UndoEvidenceKindChirho::AuthorityEvidenceRefChirho => "authority-evidence-ref-chirho",
        UndoEvidenceKindChirho::SubjectRefChirho => "subject-ref-chirho",
    }
}

fn action_kind_chirho(action_chirho: &UndoActionChirho) -> &'static str {
    match action_chirho {
        UndoActionChirho::ConditionalRestoreChirho => "conditional-restore-chirho",
        UndoActionChirho::ConditionalDeleteChirho => "conditional-delete-chirho",
        UndoActionChirho::CorrectiveForwardChirho => "corrective-forward-chirho",
        UndoActionChirho::ManualRemediationChirho => "manual-remediation-chirho",
    }
}

fn verification_kind_chirho(verification_chirho: &UndoVerificationModeChirho) -> &'static str {
    match verification_chirho {
        UndoVerificationModeChirho::VerifyPostFingerprintChirho => "verify-post-fingerprint-chirho",
        UndoVerificationModeChirho::VerifyProviderReceiptChirho => "verify-provider-receipt-chirho",
        UndoVerificationModeChirho::VerifyAuthorityEvidenceChirho => {
            "verify-authority-evidence-chirho"
        }
    }
}

fn residual_kind_chirho(residual_chirho: &IrreversibleResidualChirho) -> &'static str {
    match residual_chirho {
        IrreversibleResidualChirho::CallerExposureChirho => "caller-exposure-chirho",
        IrreversibleResidualChirho::ProviderWorkConsumedChirho => "provider-work-consumed-chirho",
        IrreversibleResidualChirho::ExternalVisibilityChirho => "external-visibility-chirho",
        IrreversibleResidualChirho::PublishedUrlObservedChirho => "published-url-observed-chirho",
        IrreversibleResidualChirho::ForwardOnlyAuthorityRecordChirho => {
            "forward-only-authority-record-chirho"
        }
    }
}

fn observation_reason_chirho(reason_chirho: &ObservationReasonChirho) -> &'static str {
    match reason_chirho {
        ObservationReasonChirho::ReadOnlyCapabilityChirho => "read-only-capability-chirho",
        ObservationReasonChirho::RecordedNondeterminismChirho => "recorded-nondeterminism-chirho",
        ObservationReasonChirho::AuthorityHandleOnlyChirho => "authority-handle-only-chirho",
    }
}

fn executable_dag_hashes_chirho(
    candidate_chirho: &AppSourceCandidateReportChirho,
) -> BTreeSet<HashChirho> {
    let mut dags_chirho = BTreeSet::from([candidate_chirho.root_dag_chirho.clone()]);
    dags_chirho.extend(
        candidate_chirho
            .routes_chirho
            .iter()
            .map(|route_chirho| route_chirho.dag_chirho.clone()),
    );
    dags_chirho
}

fn load_verified_undo_input_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
) -> Result<VerifiedUndoDagInputChirho> {
    let dag_chirho: DagChirho = store_chirho::get_object_chirho(root_chirho, dag_hash_chirho)
        .context("load candidate executable DAG")?;
    let mut node_defs_chirho = BTreeMap::new();
    for node_hash_chirho in &dag_chirho.nodes_chirho {
        let node_def_chirho: NodeDefChirho =
            store_chirho::get_object_chirho(root_chirho, node_hash_chirho)
                .context("load candidate DAG node definition")?;
        node_defs_chirho.insert(node_hash_chirho.clone(), node_def_chirho);
    }
    Ok(VerifiedUndoDagInputChirho {
        source_dag_chirho: dag_hash_chirho.clone(),
        dag_chirho,
        node_defs_chirho,
        pinned_config_refs_chirho: BTreeMap::new(),
    })
}
