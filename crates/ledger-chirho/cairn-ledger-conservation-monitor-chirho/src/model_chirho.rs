// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Bounded DTOs consumed by the detect-only conservation checker.

use cairn_ledger_model_chirho::ids_chirho::{
    AssetKindIdChirho, ClusterIdChirho, DigestChirho, MoneyGroupIdChirho,
};
use cairn_ledger_model_chirho::ShardEpochChirho;

/// One settlement/conservation domain. The stable money-group plus cluster pair avoids treating a
/// cluster id from another money trust root as the same domain.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConservationDomainIdChirho {
    pub money_group_chirho: MoneyGroupIdChirho,
    pub cluster_chirho: ClusterIdChirho,
}

impl ConservationDomainIdChirho {
    pub fn new_chirho(
        money_group_chirho: impl Into<String>,
        cluster_chirho: impl Into<String>,
    ) -> Self {
        Self {
            money_group_chirho: MoneyGroupIdChirho(money_group_chirho.into()),
            cluster_chirho: ClusterIdChirho(cluster_chirho.into()),
        }
    }
}

/// The one signed checkpoint cut shared by every view in a monitor snapshot.
///
/// In a multi-domain adapter, `checkpoint_digest_chirho` must name a signed composite cut manifest
/// that binds every domain-rollup source head and every independent issuer-supply source head. It is
/// never one cluster's advisory head-checkpoint digest. The verified signed domain and stable-kind
/// registries, not a self-declared manifest field, define the exact required scope set. The manifest
/// must bind that registry-attested set at the cut so omitting an entire scope fails closed.
///
/// `epoch_chirho` and `covered_record_count_chirho` are evidence metadata only. They neither
/// authorize a balance nor prove that independent shard epochs are equal. The verified composite
/// manifest provides the cut authority in the owning adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConservationHeadCoordinateChirho {
    pub epoch_chirho: ShardEpochChirho,
    pub checkpoint_digest_chirho: DigestChirho,
    pub covered_record_count_chirho: u64,
}

/// A verified projection rollup for one `(domain, stable asset kind)` at the snapshot head.
///
/// Values are unsigned because admission forbids negative account balances and supply. The checker
/// uses checked `u128` arithmetic so aggregating many `u64` ledger counters cannot wrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainKindConservationRollupChirho {
    pub domain_chirho: ConservationDomainIdChirho,
    pub kind_id_chirho: AssetKindIdChirho,
    pub account_net_chirho: u128,
    pub local_supply_chirho: u128,
}

/// The independent authoritative issuer supply for one money trust root and stable asset kind.
///
/// This is not derived from [`DomainKindConservationRollupChirho`]. The adapter obtains it from the
/// verified R2 mint-minus-burn aggregate so the global comparison can detect a projection that
/// fabricated internally balanced local-supply allocations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalKindSupplyChirho {
    pub money_group_chirho: MoneyGroupIdChirho,
    pub kind_id_chirho: AssetKindIdChirho,
    pub supply_chirho: u128,
}

/// One complete verified-view triple at a single signed cut.
///
/// The head coordinate occurs once, so consumers cannot accidentally compare two explicitly
/// different cuts. Implementations of
/// [`crate::ports_chirho::VerifiedConservationSnapshotPortChirho`] must still verify every source
/// and prove that the account rollups, local-supply allocations, and independent issuer supplies
/// came from that cut before constructing this DTO. This crate does not expose or accept raw rows
/// through its port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadConsistentConservationSnapshotChirho {
    pub head_chirho: ConservationHeadCoordinateChirho,
    pub rollups_chirho: Vec<DomainKindConservationRollupChirho>,
    pub global_supplies_chirho: Vec<GlobalKindSupplyChirho>,
}
