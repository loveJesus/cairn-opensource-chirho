// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Derive one conservation snapshot from verified ledger records via TWO independent paths.
//!
//! The rehearsal Phase A seam (#5294) closed under the #5298 placement ruling: the derivation
//! LOGIC lives here (audit already speaks the record grammar), the monitor crate stays
//! structurally independent (it never links this crate or any journal), and the JOURNAL WALK
//! stays the caller's job — the composition crate feeds already-verified records in and wires
//! the result into [`cairn_ledger_conservation_monitor_chirho`]'s snapshot port via a thin
//! newtype. This crate reads no storage at runtime.
//!
//! Independence law inside the derivation itself: `account_net` comes from the LEG fold
//! ([`crate::fold_leg_chirho`]) while `local_supply`/global supply come from the MINT/BURN OP
//! scan — two derivations over the same verified records, so a doctored leg and a doctored
//! mint each break the equations they did not feed. Scope: one journal = one conservation
//! domain (the caller names it); the multi-domain composite-cut manifest remains the recorded
//! host-side follow-up per the monitor port's own doc.

use std::collections::BTreeMap;

use cairn_ledger_conservation_monitor_chirho::model_chirho::{
    ConservationDomainIdChirho, ConservationHeadCoordinateChirho,
    DomainKindConservationRollupChirho, GlobalKindSupplyChirho,
    HeadConsistentConservationSnapshotChirho,
};
use cairn_ledger_model_chirho::ids_chirho::AssetKindIdChirho;
use cairn_ledger_model_chirho::record_chirho::{
    LedgerOpChirho, LedgerRecordChirho, LegDeltaChirho,
};

use crate::{fold_leg_chirho, AccountStateChirho};

/// Why a snapshot could not be derived. Every arm is fail-closed input for the monitor's
/// `VerifiedSnapshotUnavailableChirho` side — the derivation refuses UNREPRESENTABLE states;
/// representable drift is deliberately left in the snapshot for the checker to catch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotDeriveErrorChirho {
    /// A leg fold overflowed or underflowed (e.g. a release exceeding held) at this record seq.
    LegFoldRefusedChirho { seq_chirho: u64 },
    /// An admitted account ended with net money below zero — impossible under the spendable
    /// floor, so the input records cannot all be genuinely admitted.
    NegativeAccountNetChirho { owner_chirho: String },
    /// Burns exceed mints for this kind — true supply would be negative, unrepresentable.
    BurnExceedsMintChirho { kind_id_chirho: AssetKindIdChirho },
    /// A checked u128 aggregation overflowed.
    ArithmeticOverflowChirho,
}

/// Derive the head-consistent snapshot for ONE domain from in-order, already-verified records.
///
/// The caller contract (binding): `records_chirho` is the COMPLETE record sequence of one
/// journal, in chain order, after signature/chain/canonical-byte verification — this function
/// performs arithmetic, never verification, and the composition wiring must uphold the monitor
/// port's verify-before-return contract around it. Leg `post` states are ignored: the snapshot
/// re-derives balances from deltas alone, which is exactly what makes it worth comparing.
pub fn derive_conservation_snapshot_chirho(
    records_chirho: &[LedgerRecordChirho],
    domain_chirho: ConservationDomainIdChirho,
    head_chirho: ConservationHeadCoordinateChirho,
) -> Result<HeadConsistentConservationSnapshotChirho, SnapshotDeriveErrorChirho> {
    // Path A — the LEG fold: per-(owner, kind) account states.
    let mut accounts_chirho: BTreeMap<(String, AssetKindIdChirho), AccountStateChirho> =
        BTreeMap::new();
    // Path B — the OP scan: per-kind (mints, burns) totals.
    let mut mints_chirho: BTreeMap<AssetKindIdChirho, u128> = BTreeMap::new();
    let mut burns_chirho: BTreeMap<AssetKindIdChirho, u128> = BTreeMap::new();

    for record_chirho in records_chirho {
        for leg_chirho in &record_chirho.legs_chirho {
            let key_chirho = (
                leg_chirho.account_chirho.owner_chirho.clone(),
                leg_chirho.account_chirho.kind_id_chirho.clone(),
            );
            let state_chirho = accounts_chirho.entry(key_chirho).or_default();
            *state_chirho = fold_leg_chirho(
                *state_chirho,
                &leg_chirho.delta_chirho,
                leg_chirho.amount_chirho,
            )
            .ok_or(SnapshotDeriveErrorChirho::LegFoldRefusedChirho {
                seq_chirho: record_chirho.seq_chirho,
            })?;
        }
        match &record_chirho.op_chirho {
            LedgerOpChirho::MintChirho { .. } => {
                accumulate_op_amounts_chirho(
                    record_chirho,
                    LegDeltaChirho::CreditChirho,
                    &mut mints_chirho,
                )?;
            }
            LedgerOpChirho::BurnChirho { .. } => {
                accumulate_op_amounts_chirho(
                    record_chirho,
                    LegDeltaChirho::DebitChirho,
                    &mut burns_chirho,
                )?;
            }
            // Every other op moves money between accounts (or, for Timer, not at all): the leg
            // fold sees it; supply does not. Bare Credit/Debit would shift Σnet without supply —
            // the CHECKER flags that as drift, which is the honest verdict, so no special case.
            _ => {}
        }
    }

    // Per-kind account_net (u128, checked): each account's net is >= 0 under the admitted
    // grammar (spendable floor => credits >= debits); a negative net proves bad input.
    let mut kind_nets_chirho: BTreeMap<AssetKindIdChirho, u128> = BTreeMap::new();
    for ((owner_chirho, kind_chirho), state_chirho) in &accounts_chirho {
        let net_chirho = state_chirho.net_money_chirho();
        if net_chirho < 0 {
            return Err(SnapshotDeriveErrorChirho::NegativeAccountNetChirho {
                owner_chirho: owner_chirho.clone(),
            });
        }
        let slot_chirho = kind_nets_chirho.entry(kind_chirho.clone()).or_default();
        *slot_chirho = slot_chirho
            .checked_add(net_chirho as u128)
            .ok_or(SnapshotDeriveErrorChirho::ArithmeticOverflowChirho)?;
    }

    // The kind universe is the union of both paths, so a kind seen by either derivation gets a
    // row in BOTH vectors (the checker's missing-supply / supply-without-rollup laws stay armed).
    let mut kinds_chirho: Vec<AssetKindIdChirho> = kind_nets_chirho
        .keys()
        .chain(mints_chirho.keys())
        .chain(burns_chirho.keys())
        .cloned()
        .collect();
    kinds_chirho.sort();
    kinds_chirho.dedup();

    let mut rollups_chirho = Vec::new();
    let mut global_supplies_chirho = Vec::new();
    for kind_chirho in kinds_chirho {
        let minted_chirho = mints_chirho.get(&kind_chirho).copied().unwrap_or(0);
        let burned_chirho = burns_chirho.get(&kind_chirho).copied().unwrap_or(0);
        let supply_chirho = minted_chirho.checked_sub(burned_chirho).ok_or(
            SnapshotDeriveErrorChirho::BurnExceedsMintChirho {
                kind_id_chirho: kind_chirho.clone(),
            },
        )?;
        rollups_chirho.push(DomainKindConservationRollupChirho {
            domain_chirho: domain_chirho.clone(),
            kind_id_chirho: kind_chirho.clone(),
            account_net_chirho: kind_nets_chirho.get(&kind_chirho).copied().unwrap_or(0),
            local_supply_chirho: supply_chirho,
        });
        global_supplies_chirho.push(GlobalKindSupplyChirho {
            money_group_chirho: domain_chirho.money_group_chirho.clone(),
            kind_id_chirho: kind_chirho,
            supply_chirho,
        });
    }

    Ok(HeadConsistentConservationSnapshotChirho {
        head_chirho,
        rollups_chirho,
        global_supplies_chirho,
    })
}

/// Sum this record's leg amounts of the given delta into the per-kind map (checked u128).
fn accumulate_op_amounts_chirho(
    record_chirho: &LedgerRecordChirho,
    delta_chirho: LegDeltaChirho,
    totals_chirho: &mut BTreeMap<AssetKindIdChirho, u128>,
) -> Result<(), SnapshotDeriveErrorChirho> {
    for leg_chirho in &record_chirho.legs_chirho {
        if leg_chirho.delta_chirho == delta_chirho {
            let slot_chirho = totals_chirho
                .entry(leg_chirho.account_chirho.kind_id_chirho.clone())
                .or_default();
            *slot_chirho = slot_chirho
                .checked_add(leg_chirho.amount_chirho as u128)
                .ok_or(SnapshotDeriveErrorChirho::ArithmeticOverflowChirho)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod snapshot_adapter_tests_chirho;
