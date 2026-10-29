// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Deterministic, bounded derivation from verified DAG and node-definition values.

use crate::canonical_chirho::contract_set_digest_chirho;
use crate::contract_chirho::{
    canonical_capability_bytes_chirho, canonical_capability_multiset_bytes_chirho,
    canonicalize_capabilities_chirho, selector_matches_capability_chirho,
    supporting_requirement_matches_chirho, validate_reversion_contract_set_chirho,
    BlessedReversionContractChirho, BlessedReversionContractSetChirho, CanonicalCapabilityChirho,
};
use crate::framing_chirho::{door_capability_fingerprint_chirho, validate_hash_chirho};
use crate::plan_chirho::{
    validate_undo_plan_chirho, UndoDoorKeyChirho, UndoPlanChirho, UndoPlanConfigRefChirho,
    UndoPlanEffectDoorChirho, MAX_UNDO_PLAN_DEPENDENCIES_CHIRHO, MAX_UNDO_PLAN_EFFECT_DOORS_CHIRHO,
};
use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::{DagChirho, HashChirho, NodeDefChirho};
use cairn_core_chirho::store_chirho::hash_object_chirho;
use std::collections::{BTreeMap, BTreeSet};

/// Verified values supplied by an authority-bearing caller.
///
/// The pure derivation re-hashes every value, but cannot load it from a root itself.
pub struct VerifiedUndoDagInputChirho {
    pub source_dag_chirho: HashChirho,
    pub dag_chirho: DagChirho,
    pub node_defs_chirho: BTreeMap<HashChirho, NodeDefChirho>,
    pub pinned_config_refs_chirho: BTreeMap<HashChirho, BTreeMap<String, HashChirho>>,
}

struct ResolvedDoorChirho {
    key_chirho: UndoDoorKeyChirho,
    effect_capability_chirho: CanonicalCapabilityChirho,
    supporting_capabilities_chirho: Vec<CanonicalCapabilityChirho>,
    contract_chirho: BlessedReversionContractChirho,
    config_refs_chirho: Vec<UndoPlanConfigRefChirho>,
}

/// Implements the static-undo derivation workflow documented in
/// `spec-chirho/workflows-chirho/undo-chirho/static-undo-plan-design-chirho.md`.
pub fn derive_undo_plan_chirho(
    input_chirho: &VerifiedUndoDagInputChirho,
    contract_set_chirho: &BlessedReversionContractSetChirho,
) -> Result<UndoPlanChirho> {
    validate_reversion_contract_set_chirho(contract_set_chirho)?;
    validate_verified_input_chirho(input_chirho)?;
    let order_chirho = topological_order_chirho(&input_chirho.dag_chirho)?;

    let mut resolved_by_node_chirho: BTreeMap<HashChirho, Vec<ResolvedDoorChirho>> =
        BTreeMap::new();
    let mut total_doors_chirho = 0_usize;
    for node_hash_chirho in &order_chirho {
        let node_def_chirho = input_chirho
            .node_defs_chirho
            .get(node_hash_chirho)
            .context("topological node is missing its verified definition")?;
        let config_chirho = input_chirho
            .pinned_config_refs_chirho
            .get(node_hash_chirho)
            .cloned()
            .unwrap_or_default();
        let doors_chirho = resolve_node_doors_chirho(
            node_hash_chirho,
            node_def_chirho,
            &config_chirho,
            contract_set_chirho,
        )?;
        total_doors_chirho = total_doors_chirho
            .checked_add(doors_chirho.len())
            .ok_or_else(|| anyhow::anyhow!("effect-door count overflow"))?;
        if total_doors_chirho > MAX_UNDO_PLAN_EFFECT_DOORS_CHIRHO {
            bail!("derived effect-door count exceeds the engine bound");
        }
        resolved_by_node_chirho.insert(node_hash_chirho.clone(), doors_chirho);
    }

    let incoming_nodes_chirho = incoming_node_map_chirho(&input_chirho.dag_chirho);
    let mut nearest_doors_chirho: BTreeMap<HashChirho, Vec<UndoDoorKeyChirho>> = BTreeMap::new();
    let mut dependencies_by_door_chirho: BTreeMap<UndoDoorKeyChirho, Vec<UndoDoorKeyChirho>> =
        BTreeMap::new();
    let mut total_dependencies_chirho = 0_usize;

    for node_hash_chirho in &order_chirho {
        let mut predecessors_chirho = BTreeSet::new();
        if let Some(incoming_chirho) = incoming_nodes_chirho.get(node_hash_chirho) {
            for incoming_node_chirho in incoming_chirho {
                let immediate_doors_chirho = resolved_by_node_chirho
                    .get(incoming_node_chirho)
                    .context("incoming node is absent from resolved map")?;
                if immediate_doors_chirho.is_empty() {
                    if let Some(nearest_chirho) = nearest_doors_chirho.get(incoming_node_chirho) {
                        predecessors_chirho.extend(nearest_chirho.iter().cloned());
                    }
                } else {
                    predecessors_chirho.extend(
                        immediate_doors_chirho
                            .iter()
                            .map(|door_chirho| door_chirho.key_chirho.clone()),
                    );
                }
            }
        }
        let predecessors_chirho: Vec<_> = predecessors_chirho.into_iter().collect();
        let own_doors_chirho = resolved_by_node_chirho
            .get(node_hash_chirho)
            .context("topological node is absent from resolved map")?;
        if own_doors_chirho.is_empty() {
            nearest_doors_chirho.insert(node_hash_chirho.clone(), predecessors_chirho);
        } else {
            for door_chirho in own_doors_chirho {
                total_dependencies_chirho = total_dependencies_chirho
                    .checked_add(predecessors_chirho.len())
                    .ok_or_else(|| anyhow::anyhow!("effect dependency count overflow"))?;
                if total_dependencies_chirho > MAX_UNDO_PLAN_DEPENDENCIES_CHIRHO {
                    bail!("derived effect dependency count exceeds the engine bound");
                }
                dependencies_by_door_chirho
                    .insert(door_chirho.key_chirho.clone(), predecessors_chirho.clone());
            }
            nearest_doors_chirho.insert(
                node_hash_chirho.clone(),
                own_doors_chirho
                    .iter()
                    .map(|door_chirho| door_chirho.key_chirho.clone())
                    .collect(),
            );
        }
    }

    let mut effect_doors_chirho = Vec::with_capacity(total_doors_chirho);
    for doors_chirho in resolved_by_node_chirho.into_values() {
        for door_chirho in doors_chirho {
            let depends_on_doors_chirho = dependencies_by_door_chirho
                .remove(&door_chirho.key_chirho)
                .unwrap_or_default();
            effect_doors_chirho.push(UndoPlanEffectDoorChirho {
                door_chirho: door_chirho.key_chirho,
                effect_capability_chirho: door_chirho.effect_capability_chirho,
                supporting_capabilities_chirho: door_chirho.supporting_capabilities_chirho,
                depends_on_doors_chirho,
                contract_chirho: door_chirho.contract_chirho,
                config_refs_chirho: door_chirho.config_refs_chirho,
            });
        }
    }
    effect_doors_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho.door_chirho.cmp(&right_chirho.door_chirho)
    });

    let plan_chirho = UndoPlanChirho {
        schema_chirho: crate::plan_chirho::UNDO_PLAN_SCHEMA_CHIRHO.to_string(),
        source_dag_chirho: input_chirho.source_dag_chirho.clone(),
        contract_set_digest_chirho: contract_set_digest_chirho(contract_set_chirho)?,
        max_depth_chirho: contract_set_chirho.max_depth_chirho,
        effect_doors_chirho,
    };
    validate_undo_plan_chirho(&plan_chirho)?;
    validate_plan_depth_chirho(&plan_chirho)?;
    Ok(plan_chirho)
}

fn resolve_node_doors_chirho(
    node_hash_chirho: &HashChirho,
    node_def_chirho: &NodeDefChirho,
    config_by_port_chirho: &BTreeMap<String, HashChirho>,
    contract_set_chirho: &BlessedReversionContractSetChirho,
) -> Result<Vec<ResolvedDoorChirho>> {
    let capabilities_chirho =
        canonicalize_capabilities_chirho(&node_def_chirho.capabilities_chirho)?;
    if capabilities_chirho.is_empty() {
        if !config_by_port_chirho.is_empty() {
            bail!("capability-free node cannot carry effect configuration refs");
        }
        return Ok(Vec::new());
    }
    let complete_bytes_chirho = canonical_capability_multiset_bytes_chirho(&capabilities_chirho)?;
    let mut consumed_chirho = vec![false; capabilities_chirho.len()];
    let mut matches_chirho = Vec::new();

    for (capability_index_chirho, capability_chirho) in capabilities_chirho.iter().enumerate() {
        let matching_contracts_chirho: Vec<_> = contract_set_chirho
            .contracts_chirho
            .iter()
            .filter(|contract_chirho| {
                selector_matches_capability_chirho(
                    &contract_chirho.effect_selector_chirho,
                    capability_chirho,
                )
            })
            .collect();
        match matching_contracts_chirho.as_slice() {
            [] => {}
            [contract_chirho] => {
                consumed_chirho[capability_index_chirho] = true;
                matches_chirho.push((capability_index_chirho, (*contract_chirho).clone()));
            }
            _ => bail!("one world-effect capability resolves to multiple contract keys"),
        }
    }
    if matches_chirho.is_empty() {
        bail!("capability-bearing node has no canonical world-effect door");
    }

    let mut resolved_chirho = Vec::new();
    let mut consumed_config_ports_chirho = BTreeSet::new();
    for (effect_index_chirho, contract_chirho) in matches_chirho {
        let effect_capability_chirho = capabilities_chirho[effect_index_chirho].clone();
        let mut supporting_capabilities_chirho = Vec::new();
        for requirement_chirho in &contract_chirho.supporting_requirements_chirho {
            let candidates_chirho: Vec<_> = capabilities_chirho
                .iter()
                .enumerate()
                .filter(|(index_chirho, capability_chirho)| {
                    !consumed_chirho[*index_chirho]
                        && supporting_requirement_matches_chirho(
                            requirement_chirho,
                            &effect_capability_chirho,
                            capability_chirho,
                        )
                })
                .collect();
            let [(support_index_chirho, support_chirho)] = candidates_chirho.as_slice() else {
                bail!("supporting capability requirement is absent or ambiguous");
            };
            consumed_chirho[*support_index_chirho] = true;
            supporting_capabilities_chirho.push((*support_chirho).clone());
        }
        supporting_capabilities_chirho.sort();

        let selected_bytes_chirho = canonical_capability_bytes_chirho(&effect_capability_chirho)?;
        let capability_fingerprint_chirho =
            door_capability_fingerprint_chirho(&complete_bytes_chirho, &selected_bytes_chirho)?;
        let mut config_refs_chirho = Vec::new();
        for requirement_chirho in &contract_chirho.config_ports_chirho {
            let config_ref_chirho = config_by_port_chirho
                .get(&requirement_chirho.port_chirho)
                .with_context(|| {
                    format!(
                        "missing pinned config ref for port '{}'",
                        requirement_chirho.port_chirho
                    )
                })?;
            validate_hash_chirho(config_ref_chirho, "pinned config ref")?;
            consumed_config_ports_chirho.insert(requirement_chirho.port_chirho.clone());
            config_refs_chirho.push(UndoPlanConfigRefChirho {
                port_chirho: requirement_chirho.port_chirho.clone(),
                content_chirho: config_ref_chirho.clone(),
            });
        }
        config_refs_chirho.sort();

        resolved_chirho.push(ResolvedDoorChirho {
            key_chirho: UndoDoorKeyChirho {
                effect_node_chirho: node_hash_chirho.clone(),
                capability_fingerprint_chirho,
            },
            effect_capability_chirho,
            supporting_capabilities_chirho,
            contract_chirho,
            config_refs_chirho,
        });
    }

    if let Some(unmatched_chirho) = consumed_chirho
        .iter()
        .position(|consumed_chirho| !consumed_chirho)
    {
        bail!(
            "unmatched capability residue at canonical index {unmatched_chirho}; nothing may be ignored"
        );
    }
    if config_by_port_chirho
        .keys()
        .any(|port_chirho| !consumed_config_ports_chirho.contains(port_chirho))
    {
        bail!("unmatched effect-config port residue; nothing may be ignored");
    }
    resolved_chirho
        .sort_by(|left_chirho, right_chirho| left_chirho.key_chirho.cmp(&right_chirho.key_chirho));
    if resolved_chirho
        .windows(2)
        .any(|pair_chirho| pair_chirho[0].key_chirho == pair_chirho[1].key_chirho)
    {
        bail!("two effect doors resolved to one door coordinate");
    }
    Ok(resolved_chirho)
}

fn validate_verified_input_chirho(input_chirho: &VerifiedUndoDagInputChirho) -> Result<()> {
    validate_hash_chirho(&input_chirho.source_dag_chirho, "source DAG")?;
    if hash_object_chirho(&input_chirho.dag_chirho)? != input_chirho.source_dag_chirho {
        bail!("source DAG value does not match its content address");
    }
    let dag_nodes_chirho: BTreeSet<_> = input_chirho
        .dag_chirho
        .nodes_chirho
        .iter()
        .cloned()
        .collect();
    if dag_nodes_chirho.len() != input_chirho.dag_chirho.nodes_chirho.len() {
        bail!("DAG node list contains a duplicate hash");
    }
    if dag_nodes_chirho.len() != input_chirho.node_defs_chirho.len()
        || input_chirho
            .node_defs_chirho
            .keys()
            .any(|node_chirho| !dag_nodes_chirho.contains(node_chirho))
    {
        bail!("verified node-definition map must exactly cover the DAG node set");
    }
    for (node_hash_chirho, node_def_chirho) in &input_chirho.node_defs_chirho {
        validate_hash_chirho(node_hash_chirho, "node definition")?;
        if hash_object_chirho(node_def_chirho)? != *node_hash_chirho {
            bail!("node definition value does not match its content address");
        }
    }
    if input_chirho
        .pinned_config_refs_chirho
        .keys()
        .any(|node_chirho| !dag_nodes_chirho.contains(node_chirho))
    {
        bail!("pinned config refs name a node outside the DAG");
    }
    for edge_chirho in &input_chirho.dag_chirho.edges_chirho {
        if !dag_nodes_chirho.contains(&edge_chirho.from_node_chirho)
            || !dag_nodes_chirho.contains(&edge_chirho.to_node_chirho)
        {
            bail!("DAG edge names a node outside the verified node set");
        }
    }
    Ok(())
}

fn topological_order_chirho(dag_chirho: &DagChirho) -> Result<Vec<HashChirho>> {
    let mut indegree_chirho: BTreeMap<HashChirho, usize> = dag_chirho
        .nodes_chirho
        .iter()
        .cloned()
        .map(|node_chirho| (node_chirho, 0))
        .collect();
    let mut outgoing_chirho: BTreeMap<HashChirho, Vec<HashChirho>> = BTreeMap::new();
    let mut edge_bytes_chirho = BTreeSet::new();
    for edge_chirho in &dag_chirho.edges_chirho {
        let bytes_chirho = serde_json::to_vec(edge_chirho).context("encode DAG edge")?;
        if !edge_bytes_chirho.insert(bytes_chirho) {
            bail!("DAG contains a duplicate edge");
        }
        *indegree_chirho
            .get_mut(&edge_chirho.to_node_chirho)
            .context("edge destination is absent from DAG")? += 1;
        outgoing_chirho
            .entry(edge_chirho.from_node_chirho.clone())
            .or_default()
            .push(edge_chirho.to_node_chirho.clone());
    }
    for destinations_chirho in outgoing_chirho.values_mut() {
        destinations_chirho.sort();
    }
    let mut ready_chirho: BTreeSet<HashChirho> = indegree_chirho
        .iter()
        .filter_map(|(node_chirho, degree_chirho)| {
            (*degree_chirho == 0).then_some(node_chirho.clone())
        })
        .collect();
    let mut order_chirho = Vec::with_capacity(dag_chirho.nodes_chirho.len());
    while let Some(node_chirho) = ready_chirho.pop_first() {
        order_chirho.push(node_chirho.clone());
        if let Some(destinations_chirho) = outgoing_chirho.get(&node_chirho) {
            for destination_chirho in destinations_chirho {
                let degree_chirho = indegree_chirho
                    .get_mut(destination_chirho)
                    .context("topological destination is absent")?;
                *degree_chirho = degree_chirho
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("DAG indegree underflow"))?;
                if *degree_chirho == 0 {
                    ready_chirho.insert(destination_chirho.clone());
                }
            }
        }
    }
    if order_chirho.len() != dag_chirho.nodes_chirho.len() {
        bail!("undo-plan derivation rejects a cyclic DAG");
    }
    Ok(order_chirho)
}

fn incoming_node_map_chirho(dag_chirho: &DagChirho) -> BTreeMap<HashChirho, Vec<HashChirho>> {
    let mut incoming_chirho: BTreeMap<HashChirho, BTreeSet<HashChirho>> = BTreeMap::new();
    for edge_chirho in &dag_chirho.edges_chirho {
        incoming_chirho
            .entry(edge_chirho.to_node_chirho.clone())
            .or_default()
            .insert(edge_chirho.from_node_chirho.clone());
    }
    incoming_chirho
        .into_iter()
        .map(|(node_chirho, predecessors_chirho)| {
            (node_chirho, predecessors_chirho.into_iter().collect())
        })
        .collect()
}

fn validate_plan_depth_chirho(plan_chirho: &UndoPlanChirho) -> Result<()> {
    let mut depths_chirho: BTreeMap<UndoDoorKeyChirho, u16> = BTreeMap::new();
    let mut pending_chirho: BTreeMap<UndoDoorKeyChirho, Vec<UndoDoorKeyChirho>> = plan_chirho
        .effect_doors_chirho
        .iter()
        .map(|door_chirho| {
            (
                door_chirho.door_chirho.clone(),
                door_chirho.depends_on_doors_chirho.clone(),
            )
        })
        .collect();
    while !pending_chirho.is_empty() {
        let ready_chirho: Vec<_> = pending_chirho
            .iter()
            .filter(|(_, dependencies_chirho)| {
                dependencies_chirho
                    .iter()
                    .all(|dependency_chirho| depths_chirho.contains_key(dependency_chirho))
            })
            .map(|(key_chirho, dependencies_chirho)| {
                let depth_chirho = dependencies_chirho
                    .iter()
                    .filter_map(|dependency_chirho| depths_chirho.get(dependency_chirho))
                    .copied()
                    .max()
                    .unwrap_or(0)
                    .saturating_add(1);
                (key_chirho.clone(), depth_chirho)
            })
            .collect();
        if ready_chirho.is_empty() {
            bail!("undo-plan door dependencies contain a cycle");
        }
        for (key_chirho, depth_chirho) in ready_chirho {
            if depth_chirho > plan_chirho.max_depth_chirho {
                bail!("undo-plan compensation cascade exceeds its declared depth");
            }
            pending_chirho.remove(&key_chirho);
            depths_chirho.insert(key_chirho, depth_chirho);
        }
    }
    Ok(())
}
