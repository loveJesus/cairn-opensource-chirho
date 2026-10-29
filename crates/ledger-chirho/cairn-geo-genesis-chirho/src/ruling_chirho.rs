// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Pending-ruling representation (section 4) plus the trust profile (section 8). Per coordinator
//! ruling 5, every ruling stays fully REPRESENTABLE — each enum keeps `UnresolvedChirho` and every
//! mapped option — and the ruled combination is ENFORCED by validation, not by deleting variants. At
//! 8.2a the only enforced rule is the unresolved refusal: while any field is `UnresolvedChirho`,
//! authoring/signing/derivation must refuse, named by field. Enforcing the specific ruled tokens
//! (e.g. rejecting a non-phase-split GG6) is 8.2b verify-time.

use crate::error_chirho::{GeoGenesisRefusalChirho, GeoGenesisResultChirho, GeoRulingFieldChirho};
use serde::{Deserialize, Serialize};

macro_rules! geo_ruling_resolvable_chirho {
    ($name:ident) => {
        impl $name {
            /// True unless the field is still `UnresolvedChirho`.
            pub fn is_resolved_chirho(&self) -> bool {
                !matches!(self, Self::UnresolvedChirho)
            }
        }
    };
}

/// Item-5 winner-own-term cell-advance ruling (section 4.1). No variant implies the recommendation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoCellAdvanceRulingChirho {
    UnresolvedChirho,
    WinnerForkWitnessOnDemandChirho,
    TransferredHeldAdoptedCheckpointChirho,
    AcceptedHandoffEagerAdvanceChirho,
}
geo_ruling_resolvable_chirho!(GeoCellAdvanceRulingChirho);

/// Item-7 replica-count token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoItem7ReplicaCountChirho {
    UnresolvedChirho,
    N2ZoneChirho,
    VoterQuorumChirho,
    N3SpreadChirho,
}
geo_ruling_resolvable_chirho!(GeoItem7ReplicaCountChirho);

/// Item-7 membership-freshness token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoItem7MembershipFreshnessChirho {
    UnresolvedChirho,
    SignedRosterOnlyChirho,
    RaftViewOnlyChirho,
    JoinedExactViewChirho,
}
geo_ruling_resolvable_chirho!(GeoItem7MembershipFreshnessChirho);

/// Item-7 durability token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoItem7DurabilityChirho {
    UnresolvedChirho,
    TransportAcceptedChirho,
    UniformSyncAllChirho,
    NativeDurabilityChirho,
}
geo_ruling_resolvable_chirho!(GeoItem7DurabilityChirho);

/// Item-7 closure token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoItem7ClosureChirho {
    UnresolvedChirho,
    RowOnlyClosureChirho,
    WholeRootSnapshotChirho,
    ManifestedPrefixClosureChirho,
}
geo_ruling_resolvable_chirho!(GeoItem7ClosureChirho);

/// Item-7 failure-semantics token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoItem7FailureSemanticsChirho {
    UnresolvedChirho,
    SingleStageFenceChirho,
    LocalCommitThenMirrorChirho,
    PrepareCommitFinalizeChirho,
}
geo_ruling_resolvable_chirho!(GeoItem7FailureSemanticsChirho);

/// Item-7 read-serving token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoItem7ReadServingChirho {
    UnresolvedChirho,
    SnapshotOnlyServingChirho,
    AckOnlyWriterVisibilityChirho,
    ReceiptGatedServingChirho,
}
geo_ruling_resolvable_chirho!(GeoItem7ReadServingChirho);

/// The item-7 six-token contract (section 4.2); each field independently retains `UnresolvedChirho`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoItem7RulingSetV1Chirho {
    pub replica_count_chirho: GeoItem7ReplicaCountChirho,
    pub membership_freshness_chirho: GeoItem7MembershipFreshnessChirho,
    pub durability_chirho: GeoItem7DurabilityChirho,
    pub closure_chirho: GeoItem7ClosureChirho,
    pub failure_semantics_chirho: GeoItem7FailureSemanticsChirho,
    pub read_serving_chirho: GeoItem7ReadServingChirho,
}

impl GeoItem7RulingSetV1Chirho {
    /// Refuse if any of the six tokens is unresolved, naming the first unresolved field.
    pub fn validate_resolved_chirho(&self) -> GeoGenesisResultChirho<()> {
        if !self.replica_count_chirho.is_resolved_chirho() {
            return Err(unresolved_chirho(
                GeoRulingFieldChirho::Item7ReplicaCountChirho,
            ));
        }
        if !self.membership_freshness_chirho.is_resolved_chirho() {
            return Err(unresolved_chirho(
                GeoRulingFieldChirho::Item7MembershipFreshnessChirho,
            ));
        }
        if !self.durability_chirho.is_resolved_chirho() {
            return Err(unresolved_chirho(
                GeoRulingFieldChirho::Item7DurabilityChirho,
            ));
        }
        if !self.closure_chirho.is_resolved_chirho() {
            return Err(unresolved_chirho(GeoRulingFieldChirho::Item7ClosureChirho));
        }
        if !self.failure_semantics_chirho.is_resolved_chirho() {
            return Err(unresolved_chirho(
                GeoRulingFieldChirho::Item7FailureSemanticsChirho,
            ));
        }
        if !self.read_serving_chirho.is_resolved_chirho() {
            return Err(unresolved_chirho(
                GeoRulingFieldChirho::Item7ReadServingChirho,
            ));
        }
        Ok(())
    }
}

/// GG6 ordering ruling (section 4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoGg6OrderingRulingChirho {
    UnresolvedChirho,
    StrictGg1ThroughGg7BeforeGenesisChirho,
    WiringReadyThenHostedAcceptedChirho,
}
geo_ruling_resolvable_chirho!(GeoGg6OrderingRulingChirho);

/// Geo-genesis trust profile (section 8). L.J. ruled the split option, but the type keeps every
/// option representable; validation carries the ruling at 8.2b.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoGenesisTrustProfileChirho {
    UnresolvedChirho,
    ExistingActivationAuthorityForBothChirho,
    DedicatedGeoGenesisAuthorityForBothChirho,
    SplitDedicatedPlanAndAcceptanceAuthoritiesChirho,
}
geo_ruling_resolvable_chirho!(GeoGenesisTrustProfileChirho);

/// The ruling set present byte-for-byte in both the plan and the acceptance packet (section 4). While
/// any field is unresolved, every downstream authority step refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoGenesisRulingSetV1Chirho {
    pub cell_advance_chirho: GeoCellAdvanceRulingChirho,
    pub item7_chirho: GeoItem7RulingSetV1Chirho,
    pub gg6_ordering_chirho: GeoGg6OrderingRulingChirho,
}

impl GeoGenesisRulingSetV1Chirho {
    /// Refuse if any ruling is unresolved, named by field.
    pub fn validate_resolved_chirho(&self) -> GeoGenesisResultChirho<()> {
        if !self.cell_advance_chirho.is_resolved_chirho() {
            return Err(unresolved_chirho(GeoRulingFieldChirho::CellAdvanceChirho));
        }
        self.item7_chirho.validate_resolved_chirho()?;
        if !self.gg6_ordering_chirho.is_resolved_chirho() {
            return Err(unresolved_chirho(GeoRulingFieldChirho::Gg6OrderingChirho));
        }
        Ok(())
    }
}

fn unresolved_chirho(field_chirho: GeoRulingFieldChirho) -> GeoGenesisRefusalChirho {
    GeoGenesisRefusalChirho::UnresolvedRulingChirho { field_chirho }
}
