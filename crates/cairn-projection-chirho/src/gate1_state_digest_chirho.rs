// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Gate 1 state-digest checkpoint helpers shared by anchor writers and verifiers.

use crate::semantic_billing_chirho::{
    billing_semantic_projection_state_chirho, billing_semantic_state_from_typed_records_chirho,
};
use crate::semantic_holds_chirho::{
    hold_semantic_projection_state_chirho, hold_semantic_state_from_typed_records_chirho,
};
use crate::semantic_parity_chirho::{
    ledger_semantic_projection_state_chirho, ledger_semantic_state_from_typed_entries_chirho,
};
use crate::semantic_resources_chirho::{
    resource_semantic_projection_state_chirho, resource_semantic_state_from_typed_records_chirho,
};
use crate::typed_ingestion_chirho::{
    typed_billing_compensation_records_prefix_chirho, typed_billing_policy_records_prefix_chirho,
    typed_billing_usage_records_prefix_chirho, typed_credit_hold_records_prefix_chirho,
    typed_ledger_entries_prefix_chirho, typed_resource_policy_records_prefix_chirho,
    typed_resource_policy_unset_records_prefix_chirho, typed_resource_usage_records_prefix_chirho,
};
use anyhow::{bail, Result};
use cairn_core_chirho::clsd_chirho::clsd_digest_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_gate1_chirho::{
    GATE1_BILLING_COMPENSATIONS_FAMILY_CHIRHO, GATE1_BILLING_POLICIES_FAMILY_CHIRHO,
    GATE1_BILLING_USAGE_FAMILY_CHIRHO, GATE1_CREDIT_HOLDS_FAMILY_CHIRHO,
    GATE1_LEDGER_FAMILY_CHIRHO, GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO,
    GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO, GATE1_RESOURCE_USAGE_FAMILY_CHIRHO,
};
use std::collections::BTreeMap;
use std::path::Path;

pub const GATE1_LEDGER_GROUP_CHIRHO: &str = "ledger-chirho";
pub const GATE1_HOLDS_GROUP_CHIRHO: &str = "holds-chirho";
pub const GATE1_RESOURCES_GROUP_CHIRHO: &str = "resources-chirho";
pub const GATE1_BILLING_GROUP_CHIRHO: &str = "billing-chirho";

const LEDGER_MEMBERS_CHIRHO: [&str; 1] = [GATE1_LEDGER_FAMILY_CHIRHO];
const HOLDS_MEMBERS_CHIRHO: [&str; 1] = [GATE1_CREDIT_HOLDS_FAMILY_CHIRHO];
const RESOURCE_MEMBERS_CHIRHO: [&str; 3] = [
    GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO,
    GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO,
    GATE1_RESOURCE_USAGE_FAMILY_CHIRHO,
];
const BILLING_MEMBERS_CHIRHO: [&str; 3] = [
    GATE1_BILLING_POLICIES_FAMILY_CHIRHO,
    GATE1_BILLING_USAGE_FAMILY_CHIRHO,
    GATE1_BILLING_COMPENSATIONS_FAMILY_CHIRHO,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gate1SemanticGroupSpecChirho {
    pub group_chirho: &'static str,
    pub members_chirho: &'static [&'static str],
}

pub const GATE1_SEMANTIC_GROUP_SPECS_CHIRHO: [Gate1SemanticGroupSpecChirho; 4] = [
    Gate1SemanticGroupSpecChirho {
        group_chirho: GATE1_LEDGER_GROUP_CHIRHO,
        members_chirho: &LEDGER_MEMBERS_CHIRHO,
    },
    Gate1SemanticGroupSpecChirho {
        group_chirho: GATE1_HOLDS_GROUP_CHIRHO,
        members_chirho: &HOLDS_MEMBERS_CHIRHO,
    },
    Gate1SemanticGroupSpecChirho {
        group_chirho: GATE1_RESOURCES_GROUP_CHIRHO,
        members_chirho: &RESOURCE_MEMBERS_CHIRHO,
    },
    Gate1SemanticGroupSpecChirho {
        group_chirho: GATE1_BILLING_GROUP_CHIRHO,
        members_chirho: &BILLING_MEMBERS_CHIRHO,
    },
];

pub fn gate1_semantic_group_specs_chirho() -> &'static [Gate1SemanticGroupSpecChirho] {
    &GATE1_SEMANTIC_GROUP_SPECS_CHIRHO
}

pub fn gate1_semantic_group_for_family_chirho(
    family_chirho: &str,
) -> Option<&'static Gate1SemanticGroupSpecChirho> {
    gate1_semantic_group_specs_chirho()
        .iter()
        .find(|spec_chirho| spec_chirho.members_chirho.contains(&family_chirho))
}

pub fn gate1_ring_a_semantic_state_digests_for_prefix_chirho(
    root_chirho: &Path,
    counts_chirho: &BTreeMap<String, u64>,
) -> Result<BTreeMap<String, HashChirho>> {
    let mut digests_chirho = BTreeMap::new();
    for spec_chirho in gate1_semantic_group_specs_chirho() {
        digests_chirho.insert(
            spec_chirho.group_chirho.to_string(),
            group_semantic_state_digest_for_prefix_chirho(
                root_chirho,
                spec_chirho.group_chirho,
                counts_chirho,
            )?,
        );
    }
    Ok(digests_chirho)
}

/// Part of the Gate 1 rung-3d checkpoint workflow: fold the existing rung-2 shadow reducer over
/// the raw JSONL prefix vector named by `counts_chirho`.
pub fn group_semantic_state_digest_for_prefix_chirho(
    root_chirho: &Path,
    group_chirho: &str,
    counts_chirho: &BTreeMap<String, u64>,
) -> Result<HashChirho> {
    match group_chirho {
        GATE1_LEDGER_GROUP_CHIRHO => {
            let entries_chirho = typed_ledger_entries_prefix_chirho(
                root_chirho,
                count_chirho(counts_chirho, GATE1_LEDGER_FAMILY_CHIRHO)?,
            )?;
            let state_chirho = ledger_semantic_state_from_typed_entries_chirho(&entries_chirho)?;
            Ok(clsd_digest_chirho(
                &ledger_semantic_projection_state_chirho(&state_chirho)?,
            ))
        }
        GATE1_HOLDS_GROUP_CHIRHO => {
            let records_chirho = typed_credit_hold_records_prefix_chirho(
                root_chirho,
                count_chirho(counts_chirho, GATE1_CREDIT_HOLDS_FAMILY_CHIRHO)?,
            )?;
            let state_chirho = hold_semantic_state_from_typed_records_chirho(&records_chirho)?;
            Ok(clsd_digest_chirho(&hold_semantic_projection_state_chirho(
                &state_chirho,
            )?))
        }
        GATE1_RESOURCES_GROUP_CHIRHO => {
            let policies_chirho = typed_resource_policy_records_prefix_chirho(
                root_chirho,
                count_chirho(counts_chirho, GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO)?,
            )?;
            let unsets_chirho = typed_resource_policy_unset_records_prefix_chirho(
                root_chirho,
                count_chirho(counts_chirho, GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO)?,
            )?;
            let usage_chirho = typed_resource_usage_records_prefix_chirho(
                root_chirho,
                count_chirho(counts_chirho, GATE1_RESOURCE_USAGE_FAMILY_CHIRHO)?,
            )?;
            let state_chirho = resource_semantic_state_from_typed_records_chirho(
                &policies_chirho,
                &unsets_chirho,
                &usage_chirho,
            )?;
            Ok(clsd_digest_chirho(
                &resource_semantic_projection_state_chirho(&state_chirho)?,
            ))
        }
        GATE1_BILLING_GROUP_CHIRHO => {
            let policies_chirho = typed_billing_policy_records_prefix_chirho(
                root_chirho,
                count_chirho(counts_chirho, GATE1_BILLING_POLICIES_FAMILY_CHIRHO)?,
            )?;
            let usage_chirho = typed_billing_usage_records_prefix_chirho(
                root_chirho,
                count_chirho(counts_chirho, GATE1_BILLING_USAGE_FAMILY_CHIRHO)?,
            )?;
            let compensations_chirho = typed_billing_compensation_records_prefix_chirho(
                root_chirho,
                count_chirho(counts_chirho, GATE1_BILLING_COMPENSATIONS_FAMILY_CHIRHO)?,
            )?;
            let state_chirho = billing_semantic_state_from_typed_records_chirho(
                &policies_chirho,
                &usage_chirho,
                &compensations_chirho,
            )?;
            Ok(clsd_digest_chirho(
                &billing_semantic_projection_state_chirho(&state_chirho)?,
            ))
        }
        _ => bail!("unknown Gate 1 semantic group {group_chirho}"),
    }
}

fn count_chirho(counts_chirho: &BTreeMap<String, u64>, family_chirho: &str) -> Result<u64> {
    counts_chirho
        .get(family_chirho)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("missing Gate 1 count for {family_chirho}"))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn member_order_is_explicit_and_reducer_ordered_chirho() {
        assert_eq!(
            GATE1_SEMANTIC_GROUP_SPECS_CHIRHO[2].members_chirho,
            [
                GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO,
                GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO,
                GATE1_RESOURCE_USAGE_FAMILY_CHIRHO,
            ]
        );
        assert_eq!(
            GATE1_SEMANTIC_GROUP_SPECS_CHIRHO[3].members_chirho,
            [
                GATE1_BILLING_POLICIES_FAMILY_CHIRHO,
                GATE1_BILLING_USAGE_FAMILY_CHIRHO,
                GATE1_BILLING_COMPENSATIONS_FAMILY_CHIRHO,
            ]
        );
    }
}
