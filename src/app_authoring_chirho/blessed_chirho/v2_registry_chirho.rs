// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Canonical registry-v2 message types and exact contract resolution.

use crate::model_chirho::{CapabilityChirho, NodeDefChirho};
use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_undo_plan_chirho::canonical_chirho::contract_set_digest_chirho;
use cairn_undo_plan_chirho::contract_chirho::{
    canonical_authoring_reversion_contract_set_chirho, validate_asset_op_port_binding_chirho,
    validate_reversion_contract_set_chirho, BlessedContractKeyChirho,
    BlessedReversionContractChirho, BlessedReversionContractSetChirho, CanonicalCapabilityChirho,
    EffectDoorSelectorChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[path = "v2_registry_chirho/effect_admission_chirho.rs"]
pub(crate) mod effect_admission_chirho;

pub const BLESSED_REGISTRY_V2_MESSAGE_SCHEMA_CHIRHO: &str = "blessed-registry-v2-message-chirho";

/// The exact world-effect coordinate signed by registry v2.
///
/// Paid effects are closed by subtype. There is deliberately no wildcard paid-effect coordinate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum BlessedEffectCoordinateV2Chirho {
    #[serde(rename = "clock-chirho")]
    ClockChirho,
    #[serde(rename = "random-chirho")]
    RandomChirho,
    #[serde(rename = "read-store-chirho")]
    ReadStoreChirho,
    #[serde(rename = "write-store-chirho")]
    WriteStoreChirho,
    #[serde(rename = "paid-effect-chirho")]
    PaidEffectChirho { effect_subtype_chirho: String },
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlessedEffectContractBindingV2Chirho {
    pub coordinate_chirho: BlessedEffectCoordinateV2Chirho,
    pub contract_key_chirho: BlessedContractKeyChirho,
}

/// Canonical bytes covered by the future registry-v2 instance signature.
///
/// This message is inert until the descriptor-v2 activation atomically installs the complete
/// reviewed effect inventory and wires both review and runtime admission to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlessedRegistryV2MessageChirho {
    pub schema_chirho: String,
    pub contract_set_digest_chirho: HashChirho,
    pub effect_bindings_chirho: Vec<BlessedEffectContractBindingV2Chirho>,
}

/// One exact coordinate in the descriptor-v1 to registry-v2 activation inventory.
///
/// `V2CoordinateChirho` carries every typed effect coordinate that survives activation. A
/// `LegacyKindChirho` names a v1 row that has no typed capability coordinate and may disappear only
/// when the activation packet explicitly lists it as retired. Keeping these alternatives distinct
/// prevents a broad legacy kind from masquerading as an exact paid-effect subtype.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlessedRegistryTransitionCoordinateChirho {
    V2CoordinateChirho(BlessedEffectCoordinateV2Chirho),
    LegacyKindChirho { kind_chirho: String },
}

/// The two v1 rows proven unreachable by the whole-tree reader sweep. Activation retires exactly
/// these names rather than inventing capability semantics that do not exist.
pub fn named_unreachable_registry_v1_retirements_chirho(
) -> Vec<BlessedRegistryTransitionCoordinateChirho> {
    vec![
        BlessedRegistryTransitionCoordinateChirho::LegacyKindChirho {
            kind_chirho: "human_check".to_owned(),
        },
        BlessedRegistryTransitionCoordinateChirho::LegacyKindChirho {
            kind_chirho: "write_blob".to_owned(),
        },
    ]
}

/// Proves the descriptor-v2 transition is an exact partition of the reviewed v1 inventory.
///
/// The caller supplies `legacy_inventory_chirho` from reviewed executable cards/manifests, never a
/// source-text grep. The law is executable:
///
/// `legacy == registry_v2_coordinates UNION named_retirements`, with all three sets duplicate-free
/// and the union disjoint. This is the exact-coordinate form of
/// `old_count == new_count + named_retired_count`; an omitted card, injected subtype, unnamed
/// retirement, or duplicate refuses before activation.
pub fn validate_registry_v2_transition_parity_chirho(
    legacy_inventory_chirho: &[BlessedRegistryTransitionCoordinateChirho],
    named_retirements_chirho: &[BlessedRegistryTransitionCoordinateChirho],
    message_chirho: &BlessedRegistryV2MessageChirho,
    contract_set_chirho: &BlessedReversionContractSetChirho,
) -> Result<()> {
    validate_registry_v2_message_chirho(message_chirho, contract_set_chirho)?;

    let legacy_chirho = unique_transition_coordinates_chirho(
        legacy_inventory_chirho,
        "legacy activation inventory",
    )?;
    let retired_chirho = unique_transition_coordinates_chirho(
        named_retirements_chirho,
        "named retirement inventory",
    )?;
    let active_chirho = message_chirho
        .effect_bindings_chirho
        .iter()
        .map(|binding_chirho| {
            BlessedRegistryTransitionCoordinateChirho::V2CoordinateChirho(
                binding_chirho.coordinate_chirho.clone(),
            )
        })
        .collect::<BTreeSet<_>>();

    if !active_chirho.is_disjoint(&retired_chirho) {
        bail!("an active registry-v2 coordinate is also named retired");
    }
    if !retired_chirho.is_subset(&legacy_chirho) {
        bail!("a named retirement is absent from the reviewed v1 inventory");
    }

    let expected_legacy_chirho = active_chirho
        .union(&retired_chirho)
        .cloned()
        .collect::<BTreeSet<_>>();
    if legacy_chirho != expected_legacy_chirho {
        bail!(
            "registry-v2 transition does not exactly cover the reviewed v1 inventory plus named retirements"
        );
    }
    Ok(())
}

fn unique_transition_coordinates_chirho(
    coordinates_chirho: &[BlessedRegistryTransitionCoordinateChirho],
    label_chirho: &str,
) -> Result<BTreeSet<BlessedRegistryTransitionCoordinateChirho>> {
    let set_chirho = coordinates_chirho.iter().cloned().collect::<BTreeSet<_>>();
    if set_chirho.len() != coordinates_chirho.len() {
        bail!("{label_chirho} contains a duplicate exact coordinate");
    }
    Ok(set_chirho)
}

/// Builds the current four-door authoring preview. It is evidence, never production authority.
pub fn inert_authoring_registry_v2_message_chirho() -> Result<BlessedRegistryV2MessageChirho> {
    registry_v2_message_from_contract_set_chirho(
        &canonical_authoring_reversion_contract_set_chirho(),
    )
}

/// Implements the registry-v2 portion of the static-undo workflow documented in
/// `spec-chirho/workflows-chirho/undo-chirho/static-undo-plan-design-chirho.md`.
pub fn registry_v2_message_from_contract_set_chirho(
    contract_set_chirho: &BlessedReversionContractSetChirho,
) -> Result<BlessedRegistryV2MessageChirho> {
    validate_reversion_contract_set_chirho(contract_set_chirho)?;
    let message_chirho = BlessedRegistryV2MessageChirho {
        schema_chirho: BLESSED_REGISTRY_V2_MESSAGE_SCHEMA_CHIRHO.to_string(),
        contract_set_digest_chirho: contract_set_digest_chirho(contract_set_chirho)?,
        effect_bindings_chirho: expected_bindings_chirho(contract_set_chirho)?,
    };
    validate_registry_v2_message_chirho(&message_chirho, contract_set_chirho)?;
    Ok(message_chirho)
}

pub fn canonical_registry_v2_message_bytes_chirho(
    message_chirho: &BlessedRegistryV2MessageChirho,
    contract_set_chirho: &BlessedReversionContractSetChirho,
) -> Result<Vec<u8>> {
    validate_registry_v2_message_chirho(message_chirho, contract_set_chirho)?;
    serde_json::to_vec(message_chirho).context("encode canonical blessed registry-v2 message")
}

pub fn parse_canonical_registry_v2_message_chirho(
    text_chirho: &str,
    contract_set_chirho: &BlessedReversionContractSetChirho,
) -> Result<BlessedRegistryV2MessageChirho> {
    #[derive(Deserialize)]
    struct BlessedRegistryV2SchemaProbeChirho {
        schema_chirho: String,
    }

    let probe_chirho: BlessedRegistryV2SchemaProbeChirho =
        serde_json::from_str(text_chirho).context("probe blessed registry-v2 schema")?;
    if probe_chirho.schema_chirho != BLESSED_REGISTRY_V2_MESSAGE_SCHEMA_CHIRHO {
        bail!("unsupported blessed registry-v2 message schema");
    }
    let message_chirho: BlessedRegistryV2MessageChirho =
        serde_json::from_str(text_chirho).context("decode blessed registry-v2 message")?;
    let canonical_chirho =
        canonical_registry_v2_message_bytes_chirho(&message_chirho, contract_set_chirho)?;
    if canonical_chirho != text_chirho.as_bytes() {
        bail!("blessed registry-v2 message has a byte-canonical mismatch");
    }
    Ok(message_chirho)
}

pub fn validate_registry_v2_message_chirho(
    message_chirho: &BlessedRegistryV2MessageChirho,
    contract_set_chirho: &BlessedReversionContractSetChirho,
) -> Result<()> {
    validate_reversion_contract_set_chirho(contract_set_chirho)?;
    if message_chirho.schema_chirho != BLESSED_REGISTRY_V2_MESSAGE_SCHEMA_CHIRHO {
        bail!("unsupported blessed registry-v2 message schema");
    }
    let expected_digest_chirho = contract_set_digest_chirho(contract_set_chirho)?;
    if message_chirho.contract_set_digest_chirho != expected_digest_chirho {
        bail!("blessed registry-v2 message names the wrong contract-set digest");
    }
    let expected_bindings_chirho = expected_bindings_chirho(contract_set_chirho)?;
    if message_chirho.effect_bindings_chirho != expected_bindings_chirho {
        bail!("blessed registry-v2 bindings are incomplete, stale, duplicated, or noncanonical");
    }
    Ok(())
}

/// Verifies every world-effect coordinate on one descriptor-v2 node against the exact named set.
/// Supporting capabilities are left for the independent complete-multiset undo derivation, which
/// proves that none are missing, ambiguous, or ignored.
pub(crate) fn validate_registry_v2_node_effects_chirho(
    message_chirho: &BlessedRegistryV2MessageChirho,
    contract_set_chirho: &BlessedReversionContractSetChirho,
    node_chirho: &NodeDefChirho,
) -> Result<()> {
    validate_registry_v2_message_chirho(message_chirho, contract_set_chirho)?;
    let mut world_effect_count_chirho = 0_usize;
    for capability_chirho in &node_chirho.capabilities_chirho {
        let Some(coordinate_chirho) = coordinate_for_capability_chirho(capability_chirho)? else {
            continue;
        };
        let contract_chirho = resolve_registry_v2_contract_for_coordinate_chirho(
            message_chirho,
            contract_set_chirho,
            &coordinate_chirho,
        )?;
        validate_asset_op_port_binding_chirho(contract_chirho, node_chirho)?;
        world_effect_count_chirho = world_effect_count_chirho
            .checked_add(1)
            .context("registry-v2 world-effect count overflow")?;
    }
    if !node_chirho.capabilities_chirho.is_empty() && world_effect_count_chirho == 0 {
        bail!("capability-bearing descriptor-v2 node has no registered world-effect coordinate");
    }
    Ok(())
}

fn resolve_registry_v2_contract_for_coordinate_chirho<'a>(
    message_chirho: &BlessedRegistryV2MessageChirho,
    contract_set_chirho: &'a BlessedReversionContractSetChirho,
    coordinate_chirho: &BlessedEffectCoordinateV2Chirho,
) -> Result<&'a BlessedReversionContractChirho> {
    let binding_chirho = message_chirho
        .effect_bindings_chirho
        .iter()
        .find(|binding_chirho| binding_chirho.coordinate_chirho == *coordinate_chirho)
        .context("effect coordinate is not registered under blessed registry v2")?;
    contract_set_chirho
        .contracts_chirho
        .iter()
        .find(|contract_chirho| {
            contract_chirho.contract_key_chirho == binding_chirho.contract_key_chirho
        })
        .context("registry-v2 binding names a missing reversion contract")
}

fn expected_bindings_chirho(
    contract_set_chirho: &BlessedReversionContractSetChirho,
) -> Result<Vec<BlessedEffectContractBindingV2Chirho>> {
    let mut keyed_chirho = contract_set_chirho
        .contracts_chirho
        .iter()
        .map(|contract_chirho| {
            let binding_chirho = BlessedEffectContractBindingV2Chirho {
                coordinate_chirho: coordinate_for_selector_chirho(
                    &contract_chirho.effect_selector_chirho,
                ),
                contract_key_chirho: contract_chirho.contract_key_chirho.clone(),
            };
            let key_chirho = serde_json::to_vec(&binding_chirho.coordinate_chirho)
                .context("encode registry-v2 effect coordinate")?;
            Ok((key_chirho, binding_chirho))
        })
        .collect::<Result<Vec<_>>>()?;
    keyed_chirho.sort_by(|left_chirho, right_chirho| left_chirho.0.cmp(&right_chirho.0));
    if keyed_chirho
        .windows(2)
        .any(|pair_chirho| pair_chirho[0].0 == pair_chirho[1].0)
    {
        bail!("two reversion contracts claim one registry-v2 effect coordinate");
    }
    Ok(keyed_chirho
        .into_iter()
        .map(|(_, binding_chirho)| binding_chirho)
        .collect())
}

fn coordinate_for_selector_chirho(
    selector_chirho: &EffectDoorSelectorChirho,
) -> BlessedEffectCoordinateV2Chirho {
    match selector_chirho {
        EffectDoorSelectorChirho::ClockChirho => BlessedEffectCoordinateV2Chirho::ClockChirho,
        EffectDoorSelectorChirho::RandomChirho => BlessedEffectCoordinateV2Chirho::RandomChirho,
        EffectDoorSelectorChirho::ReadStoreChirho => {
            BlessedEffectCoordinateV2Chirho::ReadStoreChirho
        }
        EffectDoorSelectorChirho::WriteStoreChirho => {
            BlessedEffectCoordinateV2Chirho::WriteStoreChirho
        }
        EffectDoorSelectorChirho::PaidEffectChirho { effect_chirho } => {
            BlessedEffectCoordinateV2Chirho::PaidEffectChirho {
                effect_subtype_chirho: effect_chirho.clone(),
            }
        }
        EffectDoorSelectorChirho::QueryChirho => BlessedEffectCoordinateV2Chirho::QueryChirho,
        EffectDoorSelectorChirho::NetChirho => BlessedEffectCoordinateV2Chirho::NetChirho,
        EffectDoorSelectorChirho::SecretRefChirho => {
            BlessedEffectCoordinateV2Chirho::SecretRefChirho
        }
        EffectDoorSelectorChirho::RealtimeSessionChirho => {
            BlessedEffectCoordinateV2Chirho::RealtimeSessionChirho
        }
        EffectDoorSelectorChirho::InvokeChirho => BlessedEffectCoordinateV2Chirho::InvokeChirho,
        EffectDoorSelectorChirho::TemplateAppDeployChirho => {
            BlessedEffectCoordinateV2Chirho::TemplateAppDeployChirho
        }
    }
}

fn coordinate_for_capability_chirho(
    capability_chirho: &CapabilityChirho,
) -> Result<Option<BlessedEffectCoordinateV2Chirho>> {
    let canonical_chirho = CanonicalCapabilityChirho::try_from_core_chirho(capability_chirho)?;
    let coordinate_chirho = match canonical_chirho {
        CanonicalCapabilityChirho::ClockChirho => {
            Some(BlessedEffectCoordinateV2Chirho::ClockChirho)
        }
        CanonicalCapabilityChirho::RandomChirho => {
            Some(BlessedEffectCoordinateV2Chirho::RandomChirho)
        }
        CanonicalCapabilityChirho::ReadStoreChirho { .. } => {
            Some(BlessedEffectCoordinateV2Chirho::ReadStoreChirho)
        }
        CanonicalCapabilityChirho::WriteStoreChirho { .. } => {
            Some(BlessedEffectCoordinateV2Chirho::WriteStoreChirho)
        }
        CanonicalCapabilityChirho::PaidEffectChirho { effect_chirho, .. } => {
            Some(BlessedEffectCoordinateV2Chirho::PaidEffectChirho {
                effect_subtype_chirho: effect_chirho,
            })
        }
        CanonicalCapabilityChirho::QueryChirho { .. } => {
            Some(BlessedEffectCoordinateV2Chirho::QueryChirho)
        }
        CanonicalCapabilityChirho::NetChirho { .. } => {
            Some(BlessedEffectCoordinateV2Chirho::NetChirho)
        }
        CanonicalCapabilityChirho::SecretRefChirho { .. } => {
            Some(BlessedEffectCoordinateV2Chirho::SecretRefChirho)
        }
        CanonicalCapabilityChirho::RealtimeSessionChirho { .. } => {
            Some(BlessedEffectCoordinateV2Chirho::RealtimeSessionChirho)
        }
        CanonicalCapabilityChirho::InvokeChirho { .. } => {
            Some(BlessedEffectCoordinateV2Chirho::InvokeChirho)
        }
        CanonicalCapabilityChirho::TemplateAppDeployChirho { .. } => {
            Some(BlessedEffectCoordinateV2Chirho::TemplateAppDeployChirho)
        }
        CanonicalCapabilityChirho::UserIdentityChirho { .. }
        | CanonicalCapabilityChirho::AppContextChirho { .. }
        | CanonicalCapabilityChirho::SupportIssueChirho { .. }
        | CanonicalCapabilityChirho::CausalReversionChirho { .. } => None,
    };
    Ok(coordinate_chirho)
}
