// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Build a placement registry from DURABLE SIGNED EVIDENCE rather than from values a caller supplies.
//!
//! The CF8 audit's phrase for what was missing is *"production callers rather than caller-supplied
//! in-memory values"*. `PlacementRegistryChirho` is a value somebody constructs, and until now the only
//! thing that constructed one was a test. This composes it from what is on disk and verified:
//!
//! ```text
//! capacity grant  ->  RegisteredNodeChirho at ProvisionedChirho   (the entry state a grant justifies)
//! transitions     ->  advanced through the GATED advance path      (each verified, each in order)
//! ```
//!
//! **Nothing here can assert a state.** The node enters at the entry state because that is all a grant
//! justifies, and moves only through `advance_by_verified_transition_chirho`, which refuses another
//! node's transition and one signed against a state the node is not in. So a registry built by this
//! function cannot contain a `JoinedChirho` node that no signed transition put there — and `Joined` is
//! the state `admits_new_placement_chirho` keys off.
//!
//! **A node asked for without a grant REFUSES rather than being skipped.** Silently omitting it would
//! hand back a registry that looks complete and is quietly smaller than the caller asked for, and a
//! placement decision made against a short registry is the kind of wrong that reads as fine.

use crate::attestation_stores_chirho::capacity_attestation_store_chirho::{
    load_current_verified_capacity_chirho, CapacityAttestationStoreRefusalChirho,
};
use crate::attestation_stores_chirho::lifecycle_transition_store_chirho::{
    verified_transitions_in_order_chirho, LifecycleStoreRefusalChirho,
};
use crate::attestation_stores_chirho::usage_measurement_store_chirho::{
    verified_measurements_in_order_chirho, verified_measurements_in_order_for_admission_chirho,
    UsageStoreRefusalChirho,
};
use cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::NodeRegistrationAuthorityPortChirho;
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::capacity_chirho::measurement_freshness_chirho::MeasurementStampChirho;
use cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::NodeMeasurementAuthorityPortChirho;
use cairn_placement_chirho::node_lifecycle_chirho::lifecycle_attestation_chirho::LifecycleAuthorityPortChirho;
use cairn_placement_chirho::node_lifecycle_chirho::NodeLifecycleStateChirho;
use cairn_placement_chirho::placement_registry_chirho::{
    PlacementRegistryChirho, RegisteredNodeChirho,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Resolves the verifier for ONE node's own usage reports.
///
/// Per-node because usage measurements are NODE-signed, unlike capacity grants and lifecycle
/// transitions, which carry one fleet authority each. Defined here, where it is consumed, so the
/// loader stays port-shaped and testable with fixtures; the production implementor is
/// `ControlPlaneAuthoritiesChirho`, which cannot be constructed without passing its key-separation
/// check — so a registry loaded through it can never have been verified with a node's own key
/// standing in for a fleet authority.
pub trait NodeMeasurementAuthorityResolverChirho {
    /// `None` means "no verifier for this node", which the loader treats as a refusal rather than as
    /// permission to skip the node's measurements.
    fn authority_for_node_chirho(
        &self,
        node_id_chirho: &str,
    ) -> Option<&dyn NodeMeasurementAuthorityPortChirho>;
}

/// Why a registry could not be built from durable evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryLoadRefusalChirho {
    /// A node was asked for and has no verified capacity grant on record.
    NoCapacityGrantChirho { node_id_chirho: String },
    CapacityStoreChirho {
        node_id_chirho: String,
        refusal_chirho: CapacityAttestationStoreRefusalChirho,
    },
    LifecycleStoreChirho {
        node_id_chirho: String,
        refusal_chirho: LifecycleStoreRefusalChirho,
    },
    /// A verified transition would not apply to the node built from its grant. Reaching this means the
    /// two logs disagree, which is worth a distinct identity rather than a silent skip.
    TransitionDidNotApplyChirho {
        node_id_chirho: String,
        detail_chirho: String,
    },
    /// No verifier is declared for this node's own usage reports. Refused rather than skipped: a node
    /// whose measurements cannot be checked would otherwise load looking exactly like a node whose
    /// measurements were checked and found fine.
    NoMeasurementKeyForNodeChirho { node_id_chirho: String },
    UsageStoreChirho {
        node_id_chirho: String,
        refusal_chirho: UsageStoreRefusalChirho,
    },
    /// A verified measurement would not apply to the node built from its grant — the two logs name
    /// different nodes for the same evidence.
    MeasurementDidNotApplyChirho {
        node_id_chirho: String,
        detail_chirho: String,
    },
    /// The report could not be encoded for display.
    ///
    /// Its own identity, because the alternative is borrowing one that asserts something false. This
    /// says nothing about evidence: no log was read and no transition was replayed.
    RenderChirho,
}

/// Build a registry for exactly `node_ids_chirho` from durable, verified evidence.
pub fn load_verified_placement_registry_chirho(
    root_chirho: &Path,
    node_ids_chirho: &[String],
    capacity_authority_chirho: &dyn NodeRegistrationAuthorityPortChirho,
    lifecycle_authority_chirho: &dyn LifecycleAuthorityPortChirho,
    measurement_resolver_chirho: &dyn NodeMeasurementAuthorityResolverChirho,
) -> Result<PlacementRegistryChirho, RegistryLoadRefusalChirho> {
    load_verified_placement_registry_with_usage_reader_chirho(
        root_chirho,
        node_ids_chirho,
        capacity_authority_chirho,
        lifecycle_authority_chirho,
        measurement_resolver_chirho,
        verified_measurements_in_order_chirho,
    )
}

/// Build the same verified registry for an admission decision, but refuse any unverifiable usage
/// row instead of applying the report/posture reader's deliberate skip.
///
/// A caller that computes money/authority-bearing headroom must reach this named road. Keeping it
/// distinct makes it possible to census admission callers for the permissive reader; a boolean mode
/// would leave every call one literal away from silently lowering observed occupancy.
pub fn load_verified_placement_registry_for_admission_chirho(
    root_chirho: &Path,
    node_ids_chirho: &[String],
    capacity_authority_chirho: &dyn NodeRegistrationAuthorityPortChirho,
    lifecycle_authority_chirho: &dyn LifecycleAuthorityPortChirho,
    measurement_resolver_chirho: &dyn NodeMeasurementAuthorityResolverChirho,
) -> Result<PlacementRegistryChirho, RegistryLoadRefusalChirho> {
    load_verified_placement_registry_with_usage_reader_chirho(
        root_chirho,
        node_ids_chirho,
        capacity_authority_chirho,
        lifecycle_authority_chirho,
        measurement_resolver_chirho,
        verified_measurements_in_order_for_admission_chirho,
    )
}

fn load_verified_placement_registry_with_usage_reader_chirho<UsageReaderChirho>(
    root_chirho: &Path,
    node_ids_chirho: &[String],
    capacity_authority_chirho: &dyn NodeRegistrationAuthorityPortChirho,
    lifecycle_authority_chirho: &dyn LifecycleAuthorityPortChirho,
    measurement_resolver_chirho: &dyn NodeMeasurementAuthorityResolverChirho,
    usage_reader_chirho: UsageReaderChirho,
) -> Result<PlacementRegistryChirho, RegistryLoadRefusalChirho>
where
    UsageReaderChirho: Fn(
        &Path,
        &str,
        &dyn NodeMeasurementAuthorityPortChirho,
    ) -> Result<
        Vec<cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::VerifiedUsageMeasurementChirho>,
        UsageStoreRefusalChirho,
    >,
{
    let mut registry_chirho = PlacementRegistryChirho::new_chirho();
    for node_id_chirho in node_ids_chirho {
        let verified_capacity_chirho = load_current_verified_capacity_chirho(
            root_chirho,
            node_id_chirho,
            capacity_authority_chirho,
        )
        .map_err(|refusal_chirho| match refusal_chirho {
            CapacityAttestationStoreRefusalChirho::NoGrantForNodeChirho { .. } => {
                RegistryLoadRefusalChirho::NoCapacityGrantChirho {
                    node_id_chirho: node_id_chirho.clone(),
                }
            }
            other_chirho => RegistryLoadRefusalChirho::CapacityStoreChirho {
                node_id_chirho: node_id_chirho.clone(),
                refusal_chirho: other_chirho,
            },
        })?;

        // The entry state, because that is all a grant justifies.
        let mut node_chirho =
            RegisteredNodeChirho::from_verified_capacity_chirho(&verified_capacity_chirho);

        let transitions_chirho = verified_transitions_in_order_chirho(
            root_chirho,
            node_id_chirho,
            lifecycle_authority_chirho,
        )
        .map_err(
            |refusal_chirho| RegistryLoadRefusalChirho::LifecycleStoreChirho {
                node_id_chirho: node_id_chirho.clone(),
                refusal_chirho,
            },
        )?;
        for transition_chirho in transitions_chirho {
            // Through the GATED path, never by assignment. A transition that does not chain from the
            // state reached so far is skipped exactly as the store's own state derivation skips it —
            // same rule, one implementation — while a transition for the WRONG NODE cannot occur here
            // (the list is filtered by node) and is therefore a real disagreement between the logs.
            match node_chirho.advance_by_verified_transition_chirho(&transition_chirho) {
                Ok(_) => {}
                Err(refusal_chirho) => {
                    if let cairn_placement_chirho::placement_registry_chirho::LifecycleAdvanceRefusalChirho::NodeIdMismatchChirho { .. } = refusal_chirho {
                        return Err(RegistryLoadRefusalChirho::TransitionDidNotApplyChirho {
                            node_id_chirho: node_id_chirho.clone(),
                            detail_chirho: format!("{refusal_chirho:?}"),
                        });
                    }
                }
            }
        }
        // Usage measurements last, because freshness is judged against the node this evidence has
        // already built. Applied through the same GATED path as transitions: a stale report advances
        // nothing and is not an error, so a node whose latest evidence is a replay loads FROZEN rather
        // than failing the whole load — which is what "stale evidence freezes that node" asks for.
        let measurement_authority_chirho = measurement_resolver_chirho
            .authority_for_node_chirho(node_id_chirho)
            .ok_or_else(
                || RegistryLoadRefusalChirho::NoMeasurementKeyForNodeChirho {
                    node_id_chirho: node_id_chirho.clone(),
                },
            )?;
        let measurements_chirho =
            usage_reader_chirho(root_chirho, node_id_chirho, measurement_authority_chirho)
                .map_err(
                    |refusal_chirho| RegistryLoadRefusalChirho::UsageStoreChirho {
                        node_id_chirho: node_id_chirho.clone(),
                        refusal_chirho,
                    },
                )?;
        for measurement_chirho in &measurements_chirho {
            node_chirho
                .advance_by_verified_measurement_chirho(measurement_chirho)
                .map_err(|refusal_chirho| {
                    RegistryLoadRefusalChirho::MeasurementDidNotApplyChirho {
                        node_id_chirho: node_id_chirho.clone(),
                        detail_chirho: format!("{refusal_chirho:?}"),
                    }
                })?;
        }

        registry_chirho.upsert_node_chirho(node_chirho);
    }
    Ok(registry_chirho)
}

/// One node as the durable evidence describes it. Safe to print: node ids, states and capacity
/// numbers only — no key material, no paths, no request bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementControlPlaneNodeRowChirho {
    pub node_id_chirho: String,
    pub provider_chirho: String,
    pub region_chirho: String,
    pub lifecycle_chirho: NodeLifecycleStateChirho,
    pub allocatable_chirho: AllocatableCapacityChirho,
    pub reserved_chirho: AllocatableCapacityChirho,
    /// Whether the node's LIFECYCLE admits new placements. Separate from the posture below, because a
    /// node can be lifecycle-eligible and still frozen by its own measurement evidence — an operator
    /// reading one number could not tell which of the two is stopping a placement.
    pub lifecycle_admits_chirho: bool,
    pub scale_out_allowed_chirho: bool,
    pub scale_in_allowed_chirho: bool,
    /// Refusals for the probed placement, if one was probed.
    ///
    /// `None` means NOT PROBED; `Some([])` means probed and admissible. Collapsing those two into one
    /// empty list would let "nobody asked" read as "it would be admitted", which is the wrong
    /// direction for a report an operator uses to decide whether to place work.
    pub probe_refusals_chirho: Option<Vec<String>>,
}

/// A hypothetical placement to ask each node about. Reporting the refusals answers the operator's
/// actual question -- "why will a placement of this size not land here" -- while admitting nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementProbeChirho {
    pub demand_chirho: AllocatableCapacityChirho,
    pub headroom_chirho: AllocatableCapacityChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementControlPlaneReportChirho {
    pub schema_chirho: String,
    pub nodes_chirho: Vec<PlacementControlPlaneNodeRowChirho>,
}

pub const PLACEMENT_CONTROL_PLANE_REPORT_SCHEMA_V1_CHIRHO: &str =
    "placement-control-plane-report-v1-chirho";

/// Describe what a registry built from durable evidence actually says.
///
/// Reports rather than decides: it takes no demand and admits nothing. An operator asking "why will
/// nothing land on this node" needs the lifecycle and the posture SEPARATELY, since either alone can
/// be the answer.
pub fn build_placement_control_plane_report_chirho(
    registry_chirho: &PlacementRegistryChirho,
    node_ids_chirho: &[String],
    probe_chirho: Option<PlacementProbeChirho>,
) -> PlacementControlPlaneReportChirho {
    let mut nodes_chirho = Vec::new();
    for node_id_chirho in node_ids_chirho {
        let Some(node_chirho) = registry_chirho.node_chirho(node_id_chirho) else {
            continue;
        };
        let posture_chirho = node_chirho.scaling_posture_chirho();
        nodes_chirho.push(PlacementControlPlaneNodeRowChirho {
            node_id_chirho: node_chirho.node_id_chirho().to_string(),
            provider_chirho: node_chirho.domain_chirho().provider_chirho.clone(),
            region_chirho: node_chirho.domain_chirho().region_chirho.clone(),
            lifecycle_chirho: node_chirho.lifecycle_chirho(),
            allocatable_chirho: *node_chirho.allocatable_chirho(),
            reserved_chirho: registry_chirho.reserved_for_chirho(node_id_chirho),
            lifecycle_admits_chirho:
                cairn_placement_chirho::node_lifecycle_chirho::admits_new_placement_chirho(
                    node_chirho.lifecycle_chirho(),
                ),
            scale_out_allowed_chirho: posture_chirho.scale_out_allowed_chirho(),
            scale_in_allowed_chirho: posture_chirho.scale_in_allowed_chirho(),
            // The registry's own four-clause conjunction, CONSULTED rather than re-implemented.
            //
            // The offered stamp is synthesized one step past this node's own accepted baseline, and
            // that is deliberate rather than convenient. A report has no offer -- nobody is presenting
            // a measurement -- so the offer-side freshness clause has no honest input. Handing it the
            // node's own baseline (the obvious move, and what this did first) makes
            // `offered.sequence == last.sequence`, which classifies REPLAYED, so EVERY probe came back
            // refused for a reason that was an artifact of the probe rather than a fact about the
            // node. The positive-control arm caught it.
            //
            // So the synthesized stamp neutralizes that one clause, and what the probe reports is
            // exactly the clauses that depend on STORED evidence: lifecycle, the node's own posture,
            // and derived capacity against demand plus headroom. It cannot answer "is the measurement
            // accompanying this request fresh", and it does not pretend to.
            probe_refusals_chirho: probe_chirho.map(|probe_chirho| {
                let neutral_offer_chirho = node_chirho
                    .last_measurement_chirho()
                    .map(|baseline_chirho| MeasurementStampChirho {
                        hlc_millis_chirho: baseline_chirho.hlc_millis_chirho.saturating_add(1),
                        sequence_chirho: baseline_chirho.sequence_chirho.saturating_add(1),
                    })
                    .unwrap_or(MeasurementStampChirho {
                        hlc_millis_chirho: 0,
                        sequence_chirho: 0,
                    });
                registry_chirho
                    .placement_refusals_chirho(
                        node_id_chirho,
                        &probe_chirho.demand_chirho,
                        &probe_chirho.headroom_chirho,
                        neutral_offer_chirho,
                    )
                    .into_iter()
                    .map(|refusal_chirho| format!("{refusal_chirho:?}"))
                    .collect()
            }),
        });
    }
    PlacementControlPlaneReportChirho {
        schema_chirho: PLACEMENT_CONTROL_PLANE_REPORT_SCHEMA_V1_CHIRHO.to_string(),
        nodes_chirho,
    }
}

/// Encode one control-plane report for an operator.
///
/// The encode failure refuses as [`RegistryLoadRefusalChirho::RenderChirho`]. It previously borrowed
/// `TransitionDidNotApplyChirho` with an EMPTY node id, which told an operator on the
/// `placement-control-verify` path that a lifecycle transition had not applied, for a node that does
/// not exist — sending the search for evidence to a subject where none can be found, over a failure
/// that read no evidence at all.
pub fn render_placement_control_plane_report_chirho(
    report_chirho: &PlacementControlPlaneReportChirho,
) -> Result<String, RegistryLoadRefusalChirho> {
    serde_json::to_string(report_chirho)
        .map_err(|_error_chirho| RegistryLoadRefusalChirho::RenderChirho)
}

#[cfg(test)]
#[path = "placement_registry_load_tests_chirho.rs"]
mod placement_registry_load_tests_chirho;
