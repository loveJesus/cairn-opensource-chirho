// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Checked global/per-domain conservation equations over one verified snapshot.

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, MoneyGroupIdChirho};

use crate::model_chirho::{
    ConservationDomainIdChirho, ConservationHeadCoordinateChirho,
    DomainKindConservationRollupChirho, GlobalKindSupplyChirho,
    HeadConsistentConservationSnapshotChirho,
};
use crate::ports_chirho::VerifiedConservationSnapshotPortChirho;

type DomainKindKeyChirho = (ConservationDomainIdChirho, AssetKindIdChirho);
type MoneyGroupKindKeyChirho = (MoneyGroupIdChirho, AssetKindIdChirho);

/// The exact fail-closed condition found at a signed checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConservationIncidentKindChirho {
    DuplicateDomainKindRollupChirho {
        domain_chirho: ConservationDomainIdChirho,
        kind_id_chirho: AssetKindIdChirho,
    },
    DuplicateGlobalKindSupplyChirho {
        money_group_chirho: MoneyGroupIdChirho,
        kind_id_chirho: AssetKindIdChirho,
    },
    MissingGlobalKindSupplyChirho {
        money_group_chirho: MoneyGroupIdChirho,
        kind_id_chirho: AssetKindIdChirho,
    },
    GlobalSupplyWithoutDomainRollupChirho {
        money_group_chirho: MoneyGroupIdChirho,
        kind_id_chirho: AssetKindIdChirho,
    },
    ArithmeticOverflowChirho,
    DomainDriftChirho {
        domain_chirho: ConservationDomainIdChirho,
        kind_id_chirho: AssetKindIdChirho,
        account_net_chirho: u128,
        local_supply_chirho: u128,
    },
    GlobalKindDriftChirho {
        money_group_chirho: MoneyGroupIdChirho,
        kind_id_chirho: AssetKindIdChirho,
        account_net_chirho: u128,
        supply_chirho: u128,
    },
}

/// Deterministic incident material for the runtime owner to sign, retain, alarm on, and halt.
/// The pure checker itself has no writer or admission capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConservationIncidentChirho {
    pub head_chirho: ConservationHeadCoordinateChirho,
    pub kind_chirho: Box<ConservationIncidentKindChirho>,
}

/// Bounded evidence emitted only when every conservation equation is GREEN/CONSERVED.
///
/// This does not claim that every settlement completed. Settlement liveness and bilateral funding
/// belong to separate CF2 gates, not this conservation checker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConservationGreenEvidenceChirho {
    pub head_chirho: ConservationHeadCoordinateChirho,
    pub money_group_kind_scopes_checked_chirho: usize,
    pub domain_kind_rollups_checked_chirho: usize,
    pub global_supplies_checked_chirho: usize,
    pub work_items_checked_chirho: usize,
}

/// A standing check fails closed both when verified input is unavailable and when drift is found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConservationMonitorFailureChirho<ErrorChirho> {
    VerifiedSnapshotUnavailableChirho(ErrorChirho),
    IncidentChirho(ConservationIncidentChirho),
}

/// Loads one verified/head-consistent snapshot and checks it without any write capability.
pub fn run_conservation_monitor_once_chirho<PortChirho>(
    port_chirho: &PortChirho,
) -> Result<
    ConservationGreenEvidenceChirho,
    ConservationMonitorFailureChirho<PortChirho::ErrorChirho>,
>
where
    PortChirho: VerifiedConservationSnapshotPortChirho,
{
    let snapshot_chirho = port_chirho
        .load_verified_head_consistent_snapshot_chirho()
        .map_err(ConservationMonitorFailureChirho::VerifiedSnapshotUnavailableChirho)?;
    check_conservation_snapshot_chirho(&snapshot_chirho)
        .map_err(ConservationMonitorFailureChirho::IncidentChirho)
}

/// Checks global supply and every domain-local discrepancy at one signed checkpoint.
///
/// Expected work is `O(domain-kind rollups + money-group-kind issuer supplies)`. The snapshot
/// contains no record history, so this standing path cannot accidentally become `O(history)`.
pub(crate) fn check_conservation_snapshot_chirho(
    snapshot_chirho: &HeadConsistentConservationSnapshotChirho,
) -> Result<ConservationGreenEvidenceChirho, ConservationIncidentChirho> {
    let mut rollups_by_key_chirho =
        HashMap::<DomainKindKeyChirho, &DomainKindConservationRollupChirho>::new();
    for rollup_chirho in &snapshot_chirho.rollups_chirho {
        let key_chirho = (
            rollup_chirho.domain_chirho.clone(),
            rollup_chirho.kind_id_chirho.clone(),
        );
        if rollups_by_key_chirho
            .insert(key_chirho.clone(), rollup_chirho)
            .is_some()
        {
            return Err(incident_chirho(
                snapshot_chirho,
                ConservationIncidentKindChirho::DuplicateDomainKindRollupChirho {
                    domain_chirho: key_chirho.0,
                    kind_id_chirho: key_chirho.1,
                },
            ));
        }
    }

    let mut global_supplies_by_key_chirho =
        HashMap::<MoneyGroupKindKeyChirho, &GlobalKindSupplyChirho>::new();
    let mut global_supply_order_chirho = Vec::<MoneyGroupKindKeyChirho>::new();
    for supply_chirho in &snapshot_chirho.global_supplies_chirho {
        let key_chirho = (
            supply_chirho.money_group_chirho.clone(),
            supply_chirho.kind_id_chirho.clone(),
        );
        if global_supplies_by_key_chirho
            .insert(key_chirho.clone(), supply_chirho)
            .is_some()
        {
            return Err(incident_chirho(
                snapshot_chirho,
                ConservationIncidentKindChirho::DuplicateGlobalKindSupplyChirho {
                    money_group_chirho: key_chirho.0,
                    kind_id_chirho: key_chirho.1,
                },
            ));
        }
        global_supply_order_chirho.push(key_chirho);
    }

    let mut account_net_by_scope_chirho = HashMap::<MoneyGroupKindKeyChirho, u128>::new();
    let mut scope_order_chirho = Vec::<MoneyGroupKindKeyChirho>::new();
    for rollup_chirho in &snapshot_chirho.rollups_chirho {
        if rollup_chirho.account_net_chirho != rollup_chirho.local_supply_chirho {
            return Err(incident_chirho(
                snapshot_chirho,
                ConservationIncidentKindChirho::DomainDriftChirho {
                    domain_chirho: rollup_chirho.domain_chirho.clone(),
                    kind_id_chirho: rollup_chirho.kind_id_chirho.clone(),
                    account_net_chirho: rollup_chirho.account_net_chirho,
                    local_supply_chirho: rollup_chirho.local_supply_chirho,
                },
            ));
        }

        let key_chirho = (
            rollup_chirho.domain_chirho.money_group_chirho.clone(),
            rollup_chirho.kind_id_chirho.clone(),
        );
        let account_net_chirho = match account_net_by_scope_chirho.entry(key_chirho.clone()) {
            Entry::Occupied(entry_chirho) => entry_chirho.into_mut(),
            Entry::Vacant(entry_chirho) => {
                scope_order_chirho.push(key_chirho);
                entry_chirho.insert(0)
            }
        };
        *account_net_chirho = account_net_chirho
            .checked_add(rollup_chirho.account_net_chirho)
            .ok_or_else(|| {
                incident_chirho(
                    snapshot_chirho,
                    ConservationIncidentKindChirho::ArithmeticOverflowChirho,
                )
            })?;
    }

    for key_chirho in &scope_order_chirho {
        let account_net_chirho = account_net_by_scope_chirho
            .get(key_chirho)
            .copied()
            .expect("first-seen money-group-kind scope must remain in the local map");
        let supply_chirho = global_supplies_by_key_chirho
            .get(key_chirho)
            .ok_or_else(|| {
                incident_chirho(
                    snapshot_chirho,
                    ConservationIncidentKindChirho::MissingGlobalKindSupplyChirho {
                        money_group_chirho: key_chirho.0.clone(),
                        kind_id_chirho: key_chirho.1.clone(),
                    },
                )
            })?
            .supply_chirho;
        if account_net_chirho != supply_chirho {
            return Err(incident_chirho(
                snapshot_chirho,
                ConservationIncidentKindChirho::GlobalKindDriftChirho {
                    money_group_chirho: key_chirho.0.clone(),
                    kind_id_chirho: key_chirho.1.clone(),
                    account_net_chirho,
                    supply_chirho,
                },
            ));
        }
    }

    for key_chirho in global_supply_order_chirho {
        if !account_net_by_scope_chirho.contains_key(&key_chirho) {
            return Err(incident_chirho(
                snapshot_chirho,
                ConservationIncidentKindChirho::GlobalSupplyWithoutDomainRollupChirho {
                    money_group_chirho: key_chirho.0,
                    kind_id_chirho: key_chirho.1,
                },
            ));
        }
    }

    let work_items_checked_chirho = snapshot_chirho
        .rollups_chirho
        .len()
        .checked_add(snapshot_chirho.global_supplies_chirho.len())
        .ok_or_else(|| {
            incident_chirho(
                snapshot_chirho,
                ConservationIncidentKindChirho::ArithmeticOverflowChirho,
            )
        })?;

    Ok(ConservationGreenEvidenceChirho {
        head_chirho: snapshot_chirho.head_chirho.clone(),
        money_group_kind_scopes_checked_chirho: account_net_by_scope_chirho.len(),
        domain_kind_rollups_checked_chirho: snapshot_chirho.rollups_chirho.len(),
        global_supplies_checked_chirho: snapshot_chirho.global_supplies_chirho.len(),
        work_items_checked_chirho,
    })
}

fn incident_chirho(
    snapshot_chirho: &HeadConsistentConservationSnapshotChirho,
    kind_chirho: ConservationIncidentKindChirho,
) -> ConservationIncidentChirho {
    ConservationIncidentChirho {
        head_chirho: snapshot_chirho.head_chirho.clone(),
        kind_chirho: Box::new(kind_chirho),
    }
}
