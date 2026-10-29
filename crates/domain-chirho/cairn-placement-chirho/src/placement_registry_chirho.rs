// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The registry: where the placement rules stop being separate and become one admission decision.
//!
//! Every other module in this crate answers one question in isolation — does this node dominate, is
//! this measurement fresh, is reserved capacity derivable, is the lifecycle open. **Each of them was
//! correct and none of them was reachable.** This is their caller, and it exists because a rule with
//! no caller is decoration however well it is tested.
//!
//! **ADMISSION IS A CONJUNCTION, AND EVERY CLAUSE IS INDEPENDENTLY NECESSARY.** A placement is
//! admitted only if the node is known, its lifecycle is open, its measurement is fresh, and free
//! capacity covers demand plus headroom. The clauses are checked in that order for a reason — each is
//! cheaper and more fundamental than the next, and a node whose lifecycle is closed should not have
//! its capacity discussed at all. The test suite proves each clause independently: disabling any one
//! of the four admits a placement the others would refuse.
//!
//! **Reserved capacity is derived here, never stored.** The registry holds *placed demands*; reserved
//! is a fold over them, recomputed on every question. There is deliberately no `reserved` field to
//! drift out of sync with what is actually placed — the invariant is maintained by not being
//! representable.
//!
//! Pure: no I/O, no clock, no signing. The registry is a value the caller owns and persists; every
//! fact — capacity, measurement stamps, lifecycle state — is supplied, never discovered.

use super::capacity_chirho::capacity_dominance_chirho::{
    AllocatableCapacityChirho, CapacityDimensionChirho, CAPACITY_DIMENSIONS_CHIRHO,
};
use super::capacity_chirho::measurement_freshness_chirho::{
    classify_measurement_chirho, never_measured_posture_chirho, posture_for_verdict_chirho,
    MeasurementStampChirho, MeasurementVerdictChirho, ScalingPostureChirho,
};
use super::capacity_chirho::reserved_capacity_chirho::{
    admission_refusals_chirho, derive_reserved_capacity_chirho, effective_occupied_capacity_chirho,
    AdmissionRefusalChirho, PlacedDemandChirho,
};
use super::failure_domain_chirho::{
    spread_refusals_chirho, FailureDomainChirho, MinimumSpreadChirho, SpreadRefusalChirho,
};
use super::node_lifecycle_chirho::NodeLifecycleStateChirho;
use crate::capacity_chirho::capacity_attestation_chirho::VerifiedNodeCapacityChirho;
use crate::capacity_chirho::usage_measurement_attestation_chirho::VerifiedUsageMeasurementChirho;
use crate::node_lifecycle_chirho::lifecycle_attestation_chirho::VerifiedLifecycleTransitionChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One node the registry knows about.
///
/// `allocatable_chirho` is PRIVATE and has no public setter, because CF8 clause 7 requires allocatable
/// capacity to be *signed at node registration* rather than asserted by whoever builds the value. From
/// OUTSIDE this module — which is every production caller — the only way to introduce a node is
/// [`RegisteredNodeChirho::from_verified_capacity_chirho`], which takes a
/// [`VerifiedNodeCapacityChirho`](crate::capacity_chirho::capacity_attestation_chirho::VerifiedNodeCapacityChirho)
/// — a type obtainable only by verifying a registrar's signature.
///
/// **Two honest limits, stated rather than implied.** Code in THIS module — the registry's own
/// `#[path]`-included test file, and `unattested_for_test_chirho` — can still set the field directly,
/// because privacy in Rust is per-module rather than per-item; that is deliberate so capacity-arithmetic
/// arms need no signing fixture, and it is why the guarantee above is scoped to callers outside.
///
/// And serde still round-trips this struct, because the
/// registry is a value the caller owns and persists and has to come back from somewhere. So this is
/// the authorized CONSTRUCTION path, not a proof against a tampered store — rehydrating from
/// modified bytes is the caller's persistence boundary, and it is a different defence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredNodeChirho {
    /// Private for the same reason as the fields below, and this one reaches a different clause.
    /// `spread_refusals_chirho` derives the fleet's failure-domain layout by reading `domain_chirho`
    /// off every node, so a caller who could assign it after construction could verify a grant for a
    /// node in one provider/region and then relabel it — FABRICATING the minimum-domain spread that
    /// clause 12 makes a constraint, out of nodes that are all in one place. `node_id_chirho` is the
    /// same shape one field over: relabelling a node after its grant was checked.
    ///
    /// Both come from the VERIFIED grant in `from_verified_capacity_chirho` and never move again.
    node_id_chirho: String,
    domain_chirho: FailureDomainChirho,
    allocatable_chirho: AllocatableCapacityChirho,
    lifecycle_chirho: NodeLifecycleStateChirho,
    /// The last measurement stamp ACCEPTED for this node; `None` before its first.
    ///
    /// Private for the same reason as the two fields above, and the consequence here is sharper. While
    /// this was public it was also never advanced by any production code — every write set it to
    /// `None` — so admission's freshness clause compared every offered stamp against `None`, which
    /// classifies FRESH. The freeze could not fire on a real node no matter what evidence arrived.
    /// A public field made that invisible: the arms that exercise the freeze set it by hand, so they
    /// passed while nothing in production could reach the state they described.
    last_measurement_chirho: Option<MeasurementStampChirho>,
    /// Usage from the last FRESH node-signed report accepted in append order.
    ///
    /// Kept separately from `last_measurement_chirho` so capacity arithmetic consumes the load the
    /// stamp authenticates, rather than using freshness as a decorative gate. A replay or rewound
    /// report freezes the node but does not replace this value; sorting by sequence and taking the
    /// greatest report would erase exactly the replay evidence the durable store preserves.
    #[serde(default)]
    last_observed_usage_chirho: Option<AllocatableCapacityChirho>,
    /// What this node's OWN evidence says about whether it may take work, carried so a freeze in the
    /// durable log reaches admission.
    ///
    /// Without this, a replayed report only failed to advance the baseline — it did not stop anything.
    /// Admission's freshness clause judges a stamp the CALLER offers, so a caller could always offer a
    /// fresh-looking number and a node whose own latest evidence was a replay would still admit work.
    /// The clause says stale evidence freezes that node, and a node is frozen by what IT reported, not
    /// by what a requester claims.
    ///
    /// A node that has never been measured starts frozen, because clause 7 makes a fresh measurement a
    /// REQUIREMENT for admission, and the absence of one is not permission.
    scaling_posture_chirho: ScalingPostureChirho,
}

impl RegisteredNodeChirho {
    /// Introduce a node from a VERIFIED registrar grant. Node id and failure domain are taken from
    /// the grant too, so a caller cannot verify a grant for one node and register it as another.
    pub fn from_verified_capacity_chirho(verified_chirho: &VerifiedNodeCapacityChirho) -> Self {
        Self {
            node_id_chirho: verified_chirho.node_id_chirho().to_string(),
            domain_chirho: verified_chirho.domain_chirho().clone(),
            allocatable_chirho: *verified_chirho.allocatable_chirho(),
            // A capacity grant justifies exactly ONE state, and the lifecycle model says which:
            // `ProvisionedChirho` is the only state with no inbound transition, so it is the entry.
            // Taking the lifecycle as a PARAMETER here — as this did — let a caller assert
            // `JoinedChirho` with no evidence for it, which is precisely the caller-supplied in-memory
            // authority value the CF8 audit names as the gap. A node advances past Provisioned only
            // through verified lifecycle transitions, never by being constructed that way.
            lifecycle_chirho: NodeLifecycleStateChirho::ProvisionedChirho,
            last_measurement_chirho: None,
            last_observed_usage_chirho: None,
            scaling_posture_chirho: never_measured_posture_chirho(),
        }
    }

    /// This node's id, taken from the verified grant that introduced it.
    pub fn node_id_chirho(&self) -> &str {
        &self.node_id_chirho
    }

    /// This node's failure domain, taken from the verified grant that introduced it.
    pub fn domain_chirho(&self) -> &FailureDomainChirho {
        &self.domain_chirho
    }

    /// This node's attested allocatable capacity.
    pub fn allocatable_chirho(&self) -> &AllocatableCapacityChirho {
        &self.allocatable_chirho
    }

    /// The last measurement stamp accepted for this node; `None` before its first.
    pub fn last_measurement_chirho(&self) -> Option<MeasurementStampChirho> {
        self.last_measurement_chirho
    }

    /// Usage carried by the last fresh report accepted in append order.
    pub fn last_observed_usage_chirho(&self) -> Option<&AllocatableCapacityChirho> {
        self.last_observed_usage_chirho.as_ref()
    }

    /// Advance the accepted measurement from VERIFIED node-signed evidence.
    ///
    /// Returns the verdict rather than refusing on a stale report, so a caller learns about a freeze
    /// instead of having to ask for it separately — the same decision the durable usage store makes,
    /// and for the same reason: refusing leaves the previous measurement standing as current and the
    /// node looking healthy.
    ///
    /// The accepted stamp advances ONLY on a fresh verdict. A replayed or rewound report must never
    /// become the baseline the NEXT report is judged against, or a single replay silently re-anchors
    /// the node and the report after it is measured against evidence that was already refused.
    pub fn advance_by_verified_measurement_chirho(
        &mut self,
        verified_chirho: &VerifiedUsageMeasurementChirho,
    ) -> Result<MeasurementVerdictChirho, MeasurementAdvanceRefusalChirho> {
        if verified_chirho.node_id_chirho() != self.node_id_chirho {
            return Err(MeasurementAdvanceRefusalChirho::NodeIdMismatchChirho {
                registered_chirho: self.node_id_chirho.clone(),
                measured_chirho: verified_chirho.node_id_chirho().to_string(),
            });
        }
        let verdict_chirho = classify_measurement_chirho(
            self.last_measurement_chirho,
            verified_chirho.stamp_chirho(),
        );
        // The posture updates on EVERY report; the baseline advances only on a fresh one. That
        // asymmetry is the point: a replay must change what the node is allowed to do (freeze it)
        // without changing what the next report is judged against.
        self.scaling_posture_chirho = posture_for_verdict_chirho(verdict_chirho);
        if verdict_chirho.is_fresh_chirho() {
            self.last_measurement_chirho = Some(verified_chirho.stamp_chirho());
            self.last_observed_usage_chirho = Some(*verified_chirho.observed_usage_chirho());
        }
        Ok(verdict_chirho)
    }

    /// Set the accepted stamp directly, for arms in SIBLING modules that need a node with measurement
    /// history but are not testing how it got there. Not a production path: production advances only
    /// through `advance_by_verified_measurement_chirho`, which requires node-signed evidence.
    /// What this node's own evidence says about whether it may take work.
    pub fn scaling_posture_chirho(&self) -> ScalingPostureChirho {
        self.scaling_posture_chirho
    }

    #[cfg(test)]
    pub(crate) fn set_measurement_for_test_chirho(
        &mut self,
        stamp_chirho: Option<MeasurementStampChirho>,
    ) {
        // The posture moves with it: a node given a measurement is a MEASURED node, and leaving it
        // frozen here would make every arm about admission fail for a reason it is not testing.
        self.scaling_posture_chirho = match stamp_chirho {
            Some(_) => posture_for_verdict_chirho(MeasurementVerdictChirho::FreshChirho),
            None => never_measured_posture_chirho(),
        };
        self.last_measurement_chirho = stamp_chirho;
        self.last_observed_usage_chirho = stamp_chirho.map(|_| AllocatableCapacityChirho {
            cpu_millicores_chirho: 0,
            memory_bytes_chirho: 0,
            durable_bytes_chirho: 0,
        });
    }

    /// This node's current lifecycle state.
    pub fn lifecycle_chirho(&self) -> NodeLifecycleStateChirho {
        self.lifecycle_chirho
    }

    /// Advance this node by a VERIFIED lifecycle transition.
    ///
    /// The field is private and this is the only way to move it, because everything downstream keys
    /// off the state: [`crate::node_lifecycle_chirho::admits_new_placement_chirho`] is true only for
    /// `JoinedChirho`, so whatever can write "joined" can open a node to placements. Leaving the field
    /// `pub` left exactly the hole that
    /// [`Self::from_verified_capacity_chirho`] was tightened to close, one field over — a caller could
    /// construct at the entry state and then simply assign `JoinedChirho`.
    ///
    /// Refuses a transition for another node, and one signed against a state this node is not in, so a
    /// verified record cannot be applied to the wrong node or out of order.
    pub fn advance_by_verified_transition_chirho(
        &mut self,
        verified_chirho: &VerifiedLifecycleTransitionChirho,
    ) -> Result<NodeLifecycleStateChirho, LifecycleAdvanceRefusalChirho> {
        if verified_chirho.node_id_chirho() != self.node_id_chirho {
            return Err(LifecycleAdvanceRefusalChirho::NodeIdMismatchChirho {
                found_chirho: verified_chirho.node_id_chirho().to_string(),
                expected_chirho: self.node_id_chirho.clone(),
            });
        }
        if verified_chirho.from_state_chirho() != self.lifecycle_chirho {
            return Err(LifecycleAdvanceRefusalChirho::StateMismatchChirho {
                signed_against_chirho: verified_chirho.from_state_chirho(),
                actual_chirho: self.lifecycle_chirho,
            });
        }
        self.lifecycle_chirho = verified_chirho.resulting_state_chirho();
        Ok(self.lifecycle_chirho)
    }

    /// Build a node with capacity that was never attested — TEST ONLY.
    ///
    /// It exists so arms about admission, dominance and scaling twins do not each need a signing
    /// fixture to say something about capacity arithmetic. It is `cfg(test)` so no production path
    /// can reach it, which is what keeps the attested constructor the only shipping way in.
    #[cfg(test)]
    pub(crate) fn unattested_for_test_chirho(
        node_id_chirho: String,
        domain_chirho: FailureDomainChirho,
        allocatable_chirho: AllocatableCapacityChirho,
        lifecycle_chirho: NodeLifecycleStateChirho,
    ) -> Self {
        Self {
            node_id_chirho,
            domain_chirho,
            allocatable_chirho,
            lifecycle_chirho,
            last_measurement_chirho: None,
            last_observed_usage_chirho: None,
            scaling_posture_chirho: never_measured_posture_chirho(),
        }
    }
}

/// Why a verified transition could not be applied to this node. Distinct from the transition being
/// invalid: the record verified, it simply does not belong to this node or this moment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleAdvanceRefusalChirho {
    NodeIdMismatchChirho {
        found_chirho: String,
        expected_chirho: String,
    },
    StateMismatchChirho {
        signed_against_chirho: NodeLifecycleStateChirho,
        actual_chirho: NodeLifecycleStateChirho,
    },
}

/// What a re-grant did to a node's capacity, IN PLACE.
///
/// This is CF8 clause 9's *upgrade*, and it is genuinely not *replace*: no node is swapped, no
/// lifecycle transition occurs, and the node keeps serving throughout. Replace exchanges one node for
/// another and requires the candidate to DOMINATE; an upgrade re-grants the same node — which is why
/// `an_equal_candidate_still_replaces_chirho` is right that replacement does not imply upgrade, and
/// why upgrade needed its own path rather than a reading of replace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapacityAdvanceChirho {
    /// Strictly more in at least one dimension and less in none.
    RaisedChirho,
    /// Strictly less in at least one dimension, and still covering everything already placed here.
    LoweredChirho,
    /// The grant restates the capacity the node already had.
    UnchangedChirho,
}

/// Why a re-grant could not be applied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapacityAdvanceRefusalChirho {
    UnknownNodeChirho {
        node_id_chirho: String,
    },
    /// A re-grant naming a different failure domain would MOVE the node between domains, which is the
    /// spread-fabrication the private `domain_chirho` field exists to prevent — reachable again through
    /// a signed re-grant if this were not refused. A node that genuinely moved is a different node.
    FailureDomainChangedChirho {
        from_chirho: FailureDomainChirho,
        to_chirho: FailureDomainChirho,
    },
    /// The new capacity does not cover what is already placed here. Refused because the alternative is
    /// an instantly over-committed node: the placements do not disappear because the grant shrank.
    BelowReservedChirho {
        dimension_chirho: CapacityDimensionChirho,
        reserved_chirho: u64,
        offered_chirho: u64,
    },
}

/// Which way a capacity moved. Shared by the applying path and the reporting one, so they cannot
/// disagree about what counts as an upgrade.
fn compare_capacity_chirho(
    previous_chirho: &AllocatableCapacityChirho,
    offered_chirho: &AllocatableCapacityChirho,
) -> CapacityAdvanceChirho {
    let mut raised_chirho = false;
    let mut lowered_chirho = false;
    for dimension_chirho in CAPACITY_DIMENSIONS_CHIRHO {
        let before_chirho = previous_chirho.in_dimension_chirho(dimension_chirho);
        let after_chirho = offered_chirho.in_dimension_chirho(dimension_chirho);
        if after_chirho > before_chirho {
            raised_chirho = true;
        }
        if after_chirho < before_chirho {
            lowered_chirho = true;
        }
    }
    match (raised_chirho, lowered_chirho) {
        (false, false) => CapacityAdvanceChirho::UnchangedChirho,
        (_, true) => CapacityAdvanceChirho::LoweredChirho,
        (true, false) => CapacityAdvanceChirho::RaisedChirho,
    }
}

/// Why a verified measurement could not be applied to this node.
///
/// A STALE report is not here: it is an `Ok(verdict)`, because a replay is evidence that arrived and
/// froze the node, not an operation that failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeasurementAdvanceRefusalChirho {
    NodeIdMismatchChirho {
        registered_chirho: String,
        measured_chirho: String,
    },
}

/// Why a placement is refused. Each variant names which clause failed, so an operator is told what to
/// fix rather than that "placement failed".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlacementRefusalChirho {
    /// This node's own latest verified measurement was not fresh, or it has never been measured.
    /// Distinct from `MeasurementNotFreshChirho`, which is about the stamp a REQUESTER offered.
    FrozenByItsOwnEvidenceChirho,
    UnknownNodeChirho {
        node_id_chirho: String,
    },
    /// The node's lifecycle does not accept new work (draining, retired, or not yet joined).
    LifecycleClosedChirho {
        state_chirho: NodeLifecycleStateChirho,
    },
    /// The offered measurement is replayed or clock-rewound, so the node is frozen in both directions.
    MeasurementNotFreshChirho {
        verdict_chirho: MeasurementVerdictChirho,
    },
    /// Free capacity does not cover demand plus headroom in some dimension.
    CapacityChirho(AdmissionRefusalChirho),
}

/// Nodes plus what is placed on them. Reserved capacity is DERIVED from `placed_chirho`, never stored.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementRegistryChirho {
    nodes_chirho: BTreeMap<String, RegisteredNodeChirho>,
    placed_chirho: BTreeMap<String, Vec<PlacedDemandChirho>>,
}

impl PlacementRegistryChirho {
    pub fn new_chirho() -> Self {
        Self::default()
    }

    /// Register (or replace) a node's declared facts.
    pub fn upsert_node_chirho(&mut self, node_chirho: RegisteredNodeChirho) {
        self.nodes_chirho
            .insert(node_chirho.node_id_chirho.clone(), node_chirho);
    }

    pub fn node_chirho(&self, node_id_chirho: &str) -> Option<&RegisteredNodeChirho> {
        self.nodes_chirho.get(node_id_chirho)
    }

    /// Record an accepted placement. Callers admit first; this only records.
    pub fn record_placement_chirho(
        &mut self,
        node_id_chirho: &str,
        demand_chirho: PlacedDemandChirho,
    ) {
        self.placed_chirho
            .entry(node_id_chirho.to_string())
            .or_default()
            .push(demand_chirho);
    }

    /// How many placements this node carries. The per-node retained state the scaling twins measure:
    /// it must grow with THIS node's assignments and stay flat as the fleet grows.
    pub fn placement_count_for_chirho(&self, node_id_chirho: &str) -> usize {
        self.placed_chirho
            .get(node_id_chirho)
            .map(Vec::len)
            .unwrap_or(0)
    }

    /// Reserved capacity on one node, derived from its placed demands every time it is asked.
    pub fn reserved_for_chirho(&self, node_id_chirho: &str) -> AllocatableCapacityChirho {
        let empty_chirho: Vec<PlacedDemandChirho> = Vec::new();
        derive_reserved_capacity_chirho(
            self.placed_chirho
                .get(node_id_chirho)
                .unwrap_or(&empty_chirho),
        )
    }

    /// Conservative occupied capacity for one node.
    ///
    /// `None` means the node is unknown or has no accepted usage evidence. Callers must not turn
    /// either case into zero: that would make missing load evidence manufacture free capacity.
    pub fn effective_occupied_for_chirho(
        &self,
        node_id_chirho: &str,
    ) -> Option<AllocatableCapacityChirho> {
        let node_chirho = self.nodes_chirho.get(node_id_chirho)?;
        let observed_usage_chirho = node_chirho.last_observed_usage_chirho()?;
        Some(effective_occupied_capacity_chirho(
            &self.reserved_for_chirho(node_id_chirho),
            observed_usage_chirho,
        ))
    }

    /// Every reason this placement is refused; empty means admit.
    ///
    /// The four clauses are independently necessary — see this module's tests, which disable each in
    /// turn and show a bad placement slipping through.
    pub fn placement_refusals_chirho(
        &self,
        node_id_chirho: &str,
        demand_chirho: &AllocatableCapacityChirho,
        headroom_chirho: &AllocatableCapacityChirho,
        offered_measurement_chirho: MeasurementStampChirho,
    ) -> Vec<PlacementRefusalChirho> {
        self.admission_refusals_for_node_chirho(
            node_id_chirho,
            demand_chirho,
            headroom_chirho,
            Some(offered_measurement_chirho),
        )
    }

    /// Admission for work already represented in the placement population.
    ///
    /// Migration transfers authority for an existing placement; adding its demand again would
    /// double-count it. This checks lifecycle, the node's own durable measurement posture, and
    /// configured headroom above conservative occupied capacity with ZERO incremental demand. It
    /// takes no caller-offered stamp because the durable append-order measurement chain is the offer.
    pub fn retained_placement_refusals_chirho(
        &self,
        node_id_chirho: &str,
        headroom_chirho: &AllocatableCapacityChirho,
    ) -> Vec<PlacementRefusalChirho> {
        let zero_demand_chirho = AllocatableCapacityChirho {
            cpu_millicores_chirho: 0,
            memory_bytes_chirho: 0,
            durable_bytes_chirho: 0,
        };
        self.admission_refusals_for_node_chirho(
            node_id_chirho,
            &zero_demand_chirho,
            headroom_chirho,
            None,
        )
    }

    fn admission_refusals_for_node_chirho(
        &self,
        node_id_chirho: &str,
        demand_chirho: &AllocatableCapacityChirho,
        headroom_chirho: &AllocatableCapacityChirho,
        offered_measurement_chirho: Option<MeasurementStampChirho>,
    ) -> Vec<PlacementRefusalChirho> {
        let Some(node_chirho) = self.nodes_chirho.get(node_id_chirho) else {
            return vec![PlacementRefusalChirho::UnknownNodeChirho {
                node_id_chirho: node_id_chirho.to_string(),
            }];
        };
        let mut refusals_chirho = Vec::new();

        // 1. Lifecycle — a closed node's capacity is not worth discussing.
        if !super::node_lifecycle_chirho::admits_new_placement_chirho(node_chirho.lifecycle_chirho)
        {
            refusals_chirho.push(PlacementRefusalChirho::LifecycleClosedChirho {
                state_chirho: node_chirho.lifecycle_chirho,
            });
        }

        // 2a. The node's OWN evidence. A node whose latest verified report was a replay or a rewound
        // clock is frozen regardless of what stamp the requester offers, which is what makes the
        // clause's freeze mean something: the offered stamp below is a caller-supplied number.
        if node_chirho.last_measurement_chirho.is_none()
            || node_chirho.last_observed_usage_chirho.is_none()
            || !node_chirho
                .scaling_posture_chirho
                .scale_out_allowed_chirho()
        {
            refusals_chirho.push(PlacementRefusalChirho::FrozenByItsOwnEvidenceChirho);
        }

        // 2b. Freshness of a separate OFFER, when this is a new placement request. A retained
        // placement migration consumes the durable append-order measurement above and has no second
        // caller-authored stamp to compare.
        if let Some(offered_measurement_chirho) = offered_measurement_chirho {
            let verdict_chirho = classify_measurement_chirho(
                node_chirho.last_measurement_chirho,
                offered_measurement_chirho,
            );
            if !posture_for_verdict_chirho(verdict_chirho).scale_out_allowed_chirho() {
                refusals_chirho
                    .push(PlacementRefusalChirho::MeasurementNotFreshChirho { verdict_chirho });
            }
        }

        // 3+4. Reservation is DERIVED and observed usage is retained from node-signed evidence.
        // Their maximum is occupied capacity: either signal can close a dimension, neither can
        // erase the other, and ordinary placement usage is not counted twice.
        let occupied_chirho = self
            .effective_occupied_for_chirho(node_id_chirho)
            .unwrap_or(AllocatableCapacityChirho {
                cpu_millicores_chirho: u64::MAX,
                memory_bytes_chirho: u64::MAX,
                durable_bytes_chirho: u64::MAX,
            });
        refusals_chirho.extend(
            admission_refusals_chirho(
                &node_chirho.allocatable_chirho,
                &occupied_chirho,
                demand_chirho,
                headroom_chirho,
            )
            .into_iter()
            .map(PlacementRefusalChirho::CapacityChirho),
        );
        refusals_chirho
    }

    /// Would this capacity be applicable to this node? `None` means yes.
    ///
    /// Exists so a REPORTING caller can ask without holding verified evidence and without mutating.
    /// The alternative — handing out a way to construct a `VerifiedNodeCapacityChirho` for probing —
    /// would put a public constructor on the type whose whole purpose is that verification is the only
    /// way to obtain one. [`advance_node_capacity_chirho`] calls this, so there is ONE implementation
    /// and a shrink below placed demand cannot be refused in one place and allowed in the other.
    ///
    /// It does not check the failure domain, because a caller asking this question supplies only a
    /// capacity — the domain question can only arise from an actual signed re-grant, and that path
    /// checks it.
    pub fn capacity_advance_refusal_chirho(
        &self,
        node_id_chirho: &str,
        offered_chirho: &AllocatableCapacityChirho,
    ) -> Option<CapacityAdvanceRefusalChirho> {
        if !self.nodes_chirho.contains_key(node_id_chirho) {
            return Some(CapacityAdvanceRefusalChirho::UnknownNodeChirho {
                node_id_chirho: node_id_chirho.to_string(),
            });
        }
        let reserved_chirho = self.reserved_for_chirho(node_id_chirho);
        for dimension_chirho in CAPACITY_DIMENSIONS_CHIRHO {
            let offered_value_chirho = offered_chirho.in_dimension_chirho(dimension_chirho);
            let reserved_value_chirho = reserved_chirho.in_dimension_chirho(dimension_chirho);
            if offered_value_chirho < reserved_value_chirho {
                return Some(CapacityAdvanceRefusalChirho::BelowReservedChirho {
                    dimension_chirho,
                    reserved_chirho: reserved_value_chirho,
                    offered_chirho: offered_value_chirho,
                });
            }
        }
        None
    }

    /// What a capacity would do to this node, without applying it. `None` for an unknown node.
    pub fn capacity_advance_outcome_chirho(
        &self,
        node_id_chirho: &str,
        offered_chirho: &AllocatableCapacityChirho,
    ) -> Option<CapacityAdvanceChirho> {
        let node_chirho = self.nodes_chirho.get(node_id_chirho)?;
        Some(compare_capacity_chirho(
            &node_chirho.allocatable_chirho,
            offered_chirho,
        ))
    }

    /// Apply a re-grant to a node's capacity IN PLACE — CF8 clause 9's *upgrade*.
    ///
    /// **On the registry rather than on the node, and that is the safety property.** The check that
    /// matters compares the new capacity against what is already RESERVED here, and only the registry
    /// can derive that from its placed demands. A node-level method would have to take reserved as a
    /// parameter, and a caller that understated it could shrink a node below its own placements.
    ///
    /// Refuses a domain change, because a signed re-grant is otherwise a way to move a node between
    /// failure domains and fabricate the spread clause 12 constrains — the same hole the private
    /// `domain_chirho` field closes, reachable again through re-granting if this did not refuse.
    ///
    /// A LOWERING is allowed when it still covers what is placed: resizing a node down is legitimate,
    /// and refusing it would make capacity a ratchet.
    pub fn advance_node_capacity_chirho(
        &mut self,
        verified_chirho: &VerifiedNodeCapacityChirho,
    ) -> Result<CapacityAdvanceChirho, CapacityAdvanceRefusalChirho> {
        let node_id_chirho = verified_chirho.node_id_chirho().to_string();
        let reserved_chirho = self.reserved_for_chirho(&node_id_chirho);
        let Some(node_chirho) = self.nodes_chirho.get_mut(&node_id_chirho) else {
            return Err(CapacityAdvanceRefusalChirho::UnknownNodeChirho { node_id_chirho });
        };
        if verified_chirho.domain_chirho() != &node_chirho.domain_chirho {
            return Err(CapacityAdvanceRefusalChirho::FailureDomainChangedChirho {
                from_chirho: node_chirho.domain_chirho.clone(),
                to_chirho: verified_chirho.domain_chirho().clone(),
            });
        }
        let offered_chirho = *verified_chirho.allocatable_chirho();
        for dimension_chirho in CAPACITY_DIMENSIONS_CHIRHO {
            let offered_value_chirho = offered_chirho.in_dimension_chirho(dimension_chirho);
            let reserved_value_chirho = reserved_chirho.in_dimension_chirho(dimension_chirho);
            if offered_value_chirho < reserved_value_chirho {
                return Err(CapacityAdvanceRefusalChirho::BelowReservedChirho {
                    dimension_chirho,
                    reserved_chirho: reserved_value_chirho,
                    offered_chirho: offered_value_chirho,
                });
            }
        }
        let previous_chirho = node_chirho.allocatable_chirho;
        node_chirho.allocatable_chirho = offered_chirho;
        Ok(compare_capacity_chirho(&previous_chirho, &offered_chirho))
    }

    /// Does the CURRENT layout of nodes meet a minimum failure-domain spread?
    pub fn spread_refusals_chirho(
        &self,
        minimum_chirho: MinimumSpreadChirho,
    ) -> Vec<SpreadRefusalChirho> {
        let layout_chirho = self
            .nodes_chirho
            .values()
            .map(|node_chirho| node_chirho.domain_chirho.clone())
            .collect::<Vec<_>>();
        spread_refusals_chirho(&layout_chirho, minimum_chirho)
    }
}

#[cfg(test)]
#[path = "placement_registry_tests_chirho.rs"]
mod placement_registry_tests_chirho;
