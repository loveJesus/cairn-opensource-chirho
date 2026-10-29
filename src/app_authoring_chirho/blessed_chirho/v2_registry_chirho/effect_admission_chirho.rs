// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Unforgeable-in-crate admission capability for effect execution and replay.

use super::{
    coordinate_for_capability_chirho, registry_v2_message_from_contract_set_chirho,
    resolve_registry_v2_contract_for_coordinate_chirho, validate_registry_v2_message_chirho,
    BlessedRegistryV2MessageChirho,
};
use crate::blessed_chirho::is_blessed_chirho;
use crate::model_chirho::{CapabilityChirho, HashChirho, NodeDefChirho};
use crate::store_chirho;
use anyhow::{anyhow, bail, Context, Result};
use cairn_ledger_model_chirho::asset_op_chirho::parse_canonical_asset_op_chirho;
use cairn_undo_plan_chirho::canonical_chirho::{
    contract_set_digest_chirho, reversion_contract_digest_chirho,
};
use cairn_undo_plan_chirho::contract_chirho::{
    canonical_authoring_reversion_contract_set_chirho, canonical_capability_bytes_chirho,
    canonical_capability_multiset_bytes_chirho, canonicalize_capabilities_chirho,
    validate_asset_op_port_binding_chirho, BlessedReversionContractChirho,
    BlessedReversionContractSetChirho, EffectPricingSourceRequirementChirho,
    EffectReconciliationRequirementChirho, EffectResultCachePostureChirho,
};
use cairn_undo_plan_chirho::framing_chirho::door_capability_fingerprint_chirho;
use cairn_undo_plan_chirho::plan_chirho::UndoDoorKeyChirho;

fn resolve_registry_v2_contract_for_capability_chirho<'a>(
    message_chirho: &BlessedRegistryV2MessageChirho,
    contract_set_chirho: &'a BlessedReversionContractSetChirho,
    capability_chirho: &CapabilityChirho,
) -> Result<&'a BlessedReversionContractChirho> {
    validate_registry_v2_message_chirho(message_chirho, contract_set_chirho)?;
    let coordinate_chirho = coordinate_for_capability_chirho(capability_chirho)?
        .context("supporting capability is not a registry-v2 world-effect coordinate")?;
    resolve_registry_v2_contract_for_coordinate_chirho(
        message_chirho,
        contract_set_chirho,
        &coordinate_chirho,
    )
}

/// Proof that one exact effective capability passed either verified-node or explicit-operator
/// admission. Private fields keep construction inside this module.
pub(crate) struct EffectAdmissionChirho {
    capability_chirho: CapabilityChirho,
    asset_op_request_chirho: bool,
    descriptor_v2_chirho: Option<DescriptorV2EffectAdmissionChirho>,
}

struct DescriptorV2EffectAdmissionChirho {
    contract_set_digest_chirho: HashChirho,
    contract_chirho: BlessedReversionContractChirho,
    contract_digest_chirho: HashChirho,
    door_chirho: UndoDoorKeyChirho,
}

impl EffectAdmissionChirho {
    pub(crate) fn capability_chirho(&self) -> &CapabilityChirho {
        &self.capability_chirho
    }

    pub(crate) fn authorize_chirho(&self, capability_chirho: &CapabilityChirho) -> Result<()> {
        if &self.capability_chirho != capability_chirho {
            bail!("effect admission token does not authorize the invoked capability");
        }
        Ok(())
    }

    pub(crate) fn requires_asset_op_request_chirho(&self) -> bool {
        self.asset_op_request_chirho
    }

    pub(crate) fn contract_set_digest_chirho(&self) -> Option<&HashChirho> {
        self.descriptor_v2_chirho
            .as_ref()
            .map(|descriptor_chirho| &descriptor_chirho.contract_set_digest_chirho)
    }

    pub(crate) fn contract_chirho(&self) -> Option<&BlessedReversionContractChirho> {
        self.descriptor_v2_chirho
            .as_ref()
            .map(|descriptor_chirho| &descriptor_chirho.contract_chirho)
    }

    pub(crate) fn contract_digest_chirho(&self) -> Option<&HashChirho> {
        self.descriptor_v2_chirho
            .as_ref()
            .map(|descriptor_chirho| &descriptor_chirho.contract_digest_chirho)
    }

    pub(crate) fn door_chirho(&self) -> Option<&UndoDoorKeyChirho> {
        self.descriptor_v2_chirho
            .as_ref()
            .map(|descriptor_chirho| &descriptor_chirho.door_chirho)
    }

    pub(crate) fn reconciliation_requirement_chirho(
        &self,
    ) -> Option<&EffectReconciliationRequirementChirho> {
        self.contract_chirho()
            .and_then(|contract_chirho| contract_chirho.reconciliation_requirement_chirho.as_ref())
    }

    pub(crate) fn pricing_source_requirement_chirho(
        &self,
    ) -> Option<&EffectPricingSourceRequirementChirho> {
        self.contract_chirho()
            .and_then(|contract_chirho| contract_chirho.pricing_source_requirement_chirho.as_ref())
    }

    pub(crate) fn effect_result_cache_posture_chirho(
        &self,
    ) -> Option<&EffectResultCachePostureChirho> {
        self.contract_chirho()
            .and_then(|contract_chirho| contract_chirho.effect_result_cache_posture_chirho.as_ref())
    }

    /// Generic `RunResultChirho` and legacy effect-log reuse share this signed decision.
    ///
    /// The four pre-Descriptor-D contracts keep their historical sealed-cache behavior because
    /// their canonical bytes deliberately omit this later field. Any newly introduced contract
    /// must declare a posture; absence never infers authority from a capability subtype.
    pub(crate) fn may_reuse_generic_effect_result_chirho(&self) -> Result<bool> {
        let Some(descriptor_chirho) = &self.descriptor_v2_chirho else {
            return Ok(true);
        };
        match &descriptor_chirho
            .contract_chirho
            .effect_result_cache_posture_chirho
        {
            Some(EffectResultCachePostureChirho::NeverReuseEffectResultChirho) => Ok(false),
            Some(EffectResultCachePostureChirho::VerifiedReuseChirho) => {
                bail!("verified cache reuse requires an opaque intent-bound cache token")
            }
            None if matches!(
                descriptor_chirho
                    .contract_chirho
                    .contract_key_chirho
                    .0
                    .as_str(),
                "llm-chirho" | "query-chirho" | "template-app-deploy-chirho" | "write-store-chirho"
            ) =>
            {
                Ok(true)
            }
            None => bail!("descriptor-v2 effect contract does not declare a cache posture"),
        }
    }

    /// Applies the canonical ledger-owned request parser carried by this exact admitted door.
    pub(crate) fn authorize_request_chirho(&self, request_bytes_chirho: &[u8]) -> Result<()> {
        if self.asset_op_request_chirho {
            parse_canonical_asset_op_chirho(request_bytes_chirho)
                .context("descriptor-v2 money door refused a noncanonical AssetOp request")?;
        }
        Ok(())
    }
}

/// Issues the descriptor-v2 workflow's runtime token only after re-hashing the immutable node.
/// Workflow: `spec-chirho/workflows-chirho/undo-chirho/static-undo-plan-design-chirho.md` 4.2.1.
pub(crate) fn admit_verified_node_effect_chirho(
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    effective_capability_chirho: &CapabilityChirho,
) -> Result<EffectAdmissionChirho> {
    let contract_set_chirho = canonical_authoring_reversion_contract_set_chirho();
    let registry_message_chirho =
        registry_v2_message_from_contract_set_chirho(&contract_set_chirho)?;
    admit_verified_node_effect_against_authority_chirho(
        node_def_chirho,
        node_hash_chirho,
        effective_capability_chirho,
        &contract_set_chirho,
        &registry_message_chirho,
    )
}

fn admit_verified_node_effect_against_authority_chirho(
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    effective_capability_chirho: &CapabilityChirho,
    contract_set_chirho: &BlessedReversionContractSetChirho,
    registry_message_chirho: &BlessedRegistryV2MessageChirho,
) -> Result<EffectAdmissionChirho> {
    let actual_node_hash_chirho = store_chirho::hash_object_chirho(node_def_chirho)?;
    if &actual_node_hash_chirho != node_hash_chirho {
        bail!(
            "effect admission NodeDefChirho hash mismatch: expected {}, actual {}",
            node_hash_chirho.0,
            actual_node_hash_chirho.0
        );
    }
    let declared_capability_chirho = node_def_chirho
        .capabilities_chirho
        .iter()
        .find(|capability_chirho| !is_context_capability_chirho(capability_chirho))
        .ok_or_else(|| {
            anyhow!(
                "effect node '{}' declares no executable effect capability",
                node_def_chirho.name_chirho
            )
        })?;
    if !effective_capability_matches_declaration_chirho(
        declared_capability_chirho,
        effective_capability_chirho,
    ) {
        bail!("effect capability is not the verified node's selected executable door");
    }

    let (asset_op_request_chirho, descriptor_v2_chirho) = match &node_def_chirho
        .effect_contract_set_chirho
    {
        Some(named_set_chirho) => {
            let current_set_chirho = contract_set_digest_chirho(contract_set_chirho)?;
            if named_set_chirho != &current_set_chirho {
                bail!("descriptor-v2 effect node does not name the current verified contract set");
            }
            let contract_chirho = resolve_registry_v2_contract_for_capability_chirho(
                registry_message_chirho,
                contract_set_chirho,
                effective_capability_chirho,
            )?;
            let asset_op_request_chirho =
                validate_asset_op_port_binding_chirho(contract_chirho, node_def_chirho)?;
            let canonical_capabilities_chirho =
                canonicalize_capabilities_chirho(&node_def_chirho.capabilities_chirho)?;
            let complete_bytes_chirho =
                canonical_capability_multiset_bytes_chirho(&canonical_capabilities_chirho)?;
            let declared_canonical_chirho =
                cairn_undo_plan_chirho::contract_chirho::CanonicalCapabilityChirho::try_from_core_chirho(
                    declared_capability_chirho,
                )?;
            let selected_bytes_chirho =
                canonical_capability_bytes_chirho(&declared_canonical_chirho)?;
            let door_chirho = UndoDoorKeyChirho {
                effect_node_chirho: node_hash_chirho.clone(),
                capability_fingerprint_chirho: door_capability_fingerprint_chirho(
                    &complete_bytes_chirho,
                    &selected_bytes_chirho,
                )?,
            };
            (
                asset_op_request_chirho,
                Some(DescriptorV2EffectAdmissionChirho {
                    contract_set_digest_chirho: current_set_chirho,
                    contract_digest_chirho: reversion_contract_digest_chirho(contract_chirho)?,
                    contract_chirho: contract_chirho.clone(),
                    door_chirho,
                }),
            )
        }
        None => {
            if matches!(
                effective_capability_chirho,
                CapabilityChirho::PaidEffectChirho { .. }
            ) {
                bail!(
                    "verified pre-v2 node cannot admit charge-bearing PaidEffectChirho without descriptor-v2 authority"
                );
            }
            if !is_blessed_chirho(effective_capability_chirho) {
                bail!("verified pre-v2 node names an unblessed effect capability");
            }
            (false, None)
        }
    };

    Ok(EffectAdmissionChirho {
        capability_chirho: effective_capability_chirho.clone(),
        asset_op_request_chirho,
        descriptor_v2_chirho,
    })
}

/// Explicit node-less Rust/operator paths retain the pre-v2 registry behavior by construction.
pub(crate) fn admit_legacy_operator_effect_chirho(
    capability_chirho: &CapabilityChirho,
) -> Result<EffectAdmissionChirho> {
    if !is_blessed_chirho(capability_chirho) {
        bail!("legacy operator path names an unblessed effect capability");
    }
    Ok(EffectAdmissionChirho {
        capability_chirho: capability_chirho.clone(),
        asset_op_request_chirho: false,
        descriptor_v2_chirho: None,
    })
}

#[cfg(test)]
#[path = "effect_admission_asset_op_tests_chirho.rs"]
mod effect_admission_asset_op_tests_chirho;

fn effective_capability_matches_declaration_chirho(
    declared_chirho: &CapabilityChirho,
    effective_chirho: &CapabilityChirho,
) -> bool {
    match (declared_chirho, effective_chirho) {
        (
            CapabilityChirho::PaidEffectChirho {
                effect_chirho: declared_effect_chirho,
                ..
            },
            CapabilityChirho::PaidEffectChirho {
                effect_chirho: effective_effect_chirho,
                ..
            },
        ) => declared_effect_chirho == effective_effect_chirho,
        (
            CapabilityChirho::QueryChirho {
                prefix_chirho: declared_prefix_chirho,
                max_rows_chirho: declared_max_rows_chirho,
                ..
            },
            CapabilityChirho::QueryChirho {
                prefix_chirho: effective_prefix_chirho,
                max_rows_chirho: effective_max_rows_chirho,
                ..
            },
        ) => {
            declared_prefix_chirho == effective_prefix_chirho
                && declared_max_rows_chirho == effective_max_rows_chirho
        }
        _ => declared_chirho == effective_chirho,
    }
}

fn is_context_capability_chirho(capability_chirho: &CapabilityChirho) -> bool {
    matches!(
        capability_chirho,
        CapabilityChirho::UserIdentityChirho { .. }
            | CapabilityChirho::AppContextChirho { .. }
            | CapabilityChirho::SecretRefChirho { .. }
    )
}
