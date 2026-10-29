// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Canonical static undo-plan wire and bounded validation.

use crate::contract_chirho::{
    selector_matches_capability_chirho, supporting_requirement_matches_chirho,
    validate_reversion_contract_chirho, BlessedReversionContractChirho, CanonicalCapabilityChirho,
    MAX_COMPENSATION_CASCADE_DEPTH_CHIRHO,
};
use crate::framing_chirho::validate_hash_chirho;
use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const UNDO_PLAN_SCHEMA_CHIRHO: &str = "undo-plan-v1-chirho";
pub const MAX_UNDO_PLAN_EFFECT_DOORS_CHIRHO: usize = 4_096;
pub const MAX_UNDO_PLAN_DEPENDENCIES_CHIRHO: usize = 32_768;
pub const MAX_UNDO_PLAN_CONFIG_REFS_CHIRHO: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UndoPlanChirho {
    pub schema_chirho: String,
    pub source_dag_chirho: HashChirho,
    pub contract_set_digest_chirho: HashChirho,
    pub max_depth_chirho: u16,
    pub effect_doors_chirho: Vec<UndoPlanEffectDoorChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UndoDoorKeyChirho {
    pub effect_node_chirho: HashChirho,
    pub capability_fingerprint_chirho: HashChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UndoPlanEffectDoorChirho {
    pub door_chirho: UndoDoorKeyChirho,
    pub effect_capability_chirho: CanonicalCapabilityChirho,
    pub supporting_capabilities_chirho: Vec<CanonicalCapabilityChirho>,
    pub depends_on_doors_chirho: Vec<UndoDoorKeyChirho>,
    pub contract_chirho: BlessedReversionContractChirho,
    pub config_refs_chirho: Vec<UndoPlanConfigRefChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UndoPlanConfigRefChirho {
    pub port_chirho: String,
    pub content_chirho: HashChirho,
}

pub fn validate_undo_plan_chirho(plan_chirho: &UndoPlanChirho) -> Result<()> {
    if plan_chirho.schema_chirho != UNDO_PLAN_SCHEMA_CHIRHO {
        bail!("unsupported undo-plan schema");
    }
    validate_hash_chirho(&plan_chirho.source_dag_chirho, "source DAG")?;
    validate_hash_chirho(
        &plan_chirho.contract_set_digest_chirho,
        "contract-set digest",
    )?;
    if plan_chirho.max_depth_chirho == 0
        || plan_chirho.max_depth_chirho > MAX_COMPENSATION_CASCADE_DEPTH_CHIRHO
    {
        bail!("undo-plan cascade depth is outside the engine bound");
    }
    if plan_chirho.effect_doors_chirho.len() > MAX_UNDO_PLAN_EFFECT_DOORS_CHIRHO {
        bail!("undo-plan effect-door count exceeds the engine bound");
    }

    let mut prior_key_chirho: Option<&UndoDoorKeyChirho> = None;
    let mut known_keys_chirho = BTreeSet::new();
    let mut dependency_count_chirho = 0_usize;
    for door_chirho in &plan_chirho.effect_doors_chirho {
        validate_door_key_chirho(&door_chirho.door_chirho)?;
        if prior_key_chirho.is_some_and(|value_chirho| value_chirho >= &door_chirho.door_chirho) {
            bail!("undo-plan doors must be strictly sorted by unique door key");
        }
        prior_key_chirho = Some(&door_chirho.door_chirho);
        known_keys_chirho.insert(door_chirho.door_chirho.clone());
        validate_reversion_contract_chirho(
            &door_chirho.contract_chirho,
            plan_chirho.max_depth_chirho,
        )?;
        if !selector_matches_capability_chirho(
            &door_chirho.contract_chirho.effect_selector_chirho,
            &door_chirho.effect_capability_chirho,
        ) {
            bail!("undo-plan contract does not match its selected effect capability");
        }

        if door_chirho
            .supporting_capabilities_chirho
            .windows(2)
            .any(|pair_chirho| pair_chirho[0] >= pair_chirho[1])
        {
            bail!("supporting capabilities must be strictly sorted and unique");
        }
        if door_chirho
            .supporting_capabilities_chirho
            .contains(&door_chirho.effect_capability_chirho)
        {
            bail!("one capability cannot be both the selected effect and its support");
        }
        validate_supporting_capabilities_chirho(door_chirho)?;
        validate_sorted_dependencies_chirho(
            &door_chirho.depends_on_doors_chirho,
            &door_chirho.door_chirho,
        )?;
        dependency_count_chirho = dependency_count_chirho
            .checked_add(door_chirho.depends_on_doors_chirho.len())
            .ok_or_else(|| anyhow::anyhow!("undo-plan dependency count overflow"))?;
        validate_config_refs_chirho(&door_chirho.config_refs_chirho)?;
        if door_chirho.config_refs_chirho.len()
            != door_chirho.contract_chirho.config_ports_chirho.len()
            || door_chirho
                .config_refs_chirho
                .iter()
                .zip(&door_chirho.contract_chirho.config_ports_chirho)
                .any(|(reference_chirho, requirement_chirho)| {
                    reference_chirho.port_chirho != requirement_chirho.port_chirho
                })
        {
            bail!("undo-plan config refs do not exactly cover the contract config ports");
        }
    }
    if dependency_count_chirho > MAX_UNDO_PLAN_DEPENDENCIES_CHIRHO {
        bail!("undo-plan dependency count exceeds the engine bound");
    }
    for door_chirho in &plan_chirho.effect_doors_chirho {
        for dependency_chirho in &door_chirho.depends_on_doors_chirho {
            if !known_keys_chirho.contains(dependency_chirho) {
                bail!("undo-plan dependency names an absent effect door");
            }
        }
    }
    Ok(())
}

fn validate_door_key_chirho(key_chirho: &UndoDoorKeyChirho) -> Result<()> {
    validate_hash_chirho(&key_chirho.effect_node_chirho, "effect node")?;
    validate_hash_chirho(
        &key_chirho.capability_fingerprint_chirho,
        "capability fingerprint",
    )
}

fn validate_sorted_dependencies_chirho(
    dependencies_chirho: &[UndoDoorKeyChirho],
    own_key_chirho: &UndoDoorKeyChirho,
) -> Result<()> {
    let mut prior_chirho: Option<&UndoDoorKeyChirho> = None;
    for dependency_chirho in dependencies_chirho {
        validate_door_key_chirho(dependency_chirho)?;
        if dependency_chirho == own_key_chirho {
            bail!("effect door cannot depend on itself");
        }
        if prior_chirho.is_some_and(|value_chirho| value_chirho >= dependency_chirho) {
            bail!("door dependencies must be strictly sorted and unique");
        }
        prior_chirho = Some(dependency_chirho);
    }
    Ok(())
}

fn validate_config_refs_chirho(config_refs_chirho: &[UndoPlanConfigRefChirho]) -> Result<()> {
    if config_refs_chirho.len() > MAX_UNDO_PLAN_CONFIG_REFS_CHIRHO {
        bail!("door config-ref count exceeds the engine bound");
    }
    let mut prior_chirho: Option<&str> = None;
    for config_ref_chirho in config_refs_chirho {
        if config_ref_chirho.port_chirho.is_empty() {
            bail!("config-ref port name must be nonempty");
        }
        validate_hash_chirho(&config_ref_chirho.content_chirho, "config ref")?;
        if prior_chirho
            .is_some_and(|value_chirho| value_chirho >= config_ref_chirho.port_chirho.as_str())
        {
            bail!("config refs must be strictly sorted and unique");
        }
        prior_chirho = Some(&config_ref_chirho.port_chirho);
    }
    Ok(())
}

fn validate_supporting_capabilities_chirho(door_chirho: &UndoPlanEffectDoorChirho) -> Result<()> {
    if door_chirho.supporting_capabilities_chirho.len()
        != door_chirho
            .contract_chirho
            .supporting_requirements_chirho
            .len()
    {
        bail!("undo-plan supporting capabilities do not cover the contract requirements");
    }
    let mut consumed_chirho = vec![false; door_chirho.supporting_capabilities_chirho.len()];
    for requirement_chirho in &door_chirho.contract_chirho.supporting_requirements_chirho {
        let candidates_chirho: Vec<_> = door_chirho
            .supporting_capabilities_chirho
            .iter()
            .enumerate()
            .filter(|(index_chirho, capability_chirho)| {
                !consumed_chirho[*index_chirho]
                    && supporting_requirement_matches_chirho(
                        requirement_chirho,
                        &door_chirho.effect_capability_chirho,
                        capability_chirho,
                    )
            })
            .collect();
        let [(index_chirho, _)] = candidates_chirho.as_slice() else {
            bail!("undo-plan supporting capability binding is absent or ambiguous");
        };
        consumed_chirho[*index_chirho] = true;
    }
    Ok(())
}
