// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Derivation-correctness + fail-closed tests for the snapshot adapter, run through the REAL
//! monitor checker (the audit->monitor DTO edge is exercised, never mirrored). Fixture records
//! are hand-built and NOT wire/grammar-admitted — the derivation's caller contract places
//! admission and verification upstream, so these fixtures only need leg/op arithmetic shape
//! (post states are zeroed: the derivation ignores them by design).

use super::*;
use cairn_ledger_conservation_monitor_chirho::checker_chirho::{
    run_conservation_monitor_once_chirho, ConservationIncidentKindChirho,
    ConservationMonitorFailureChirho,
};
use cairn_ledger_conservation_monitor_chirho::ports_chirho::VerifiedConservationSnapshotPortChirho;
use cairn_ledger_model_chirho::ids_chirho::{AssetKindRefChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{
    AttributionChirho, HlcChirho, LedgerLegChirho, LegPostStateChirho,
};
use cairn_ledger_model_chirho::wire_chirho::LEDGER_RECORD_SCHEMA_V1_CHIRHO;
use cairn_ledger_model_chirho::LogIdChirho;

struct FixedSnapshotPortChirho {
    snapshot_chirho: HeadConsistentConservationSnapshotChirho,
}

impl VerifiedConservationSnapshotPortChirho for FixedSnapshotPortChirho {
    type ErrorChirho = String;

    fn load_verified_head_consistent_snapshot_chirho(
        &self,
    ) -> Result<HeadConsistentConservationSnapshotChirho, Self::ErrorChirho> {
        Ok(self.snapshot_chirho.clone())
    }
}

fn leg_chirho(
    owner_chirho: &str,
    delta_chirho: LegDeltaChirho,
    amount_chirho: u64,
) -> LedgerLegChirho {
    LedgerLegChirho {
        account_chirho: LogIdChirho {
            owner_chirho: owner_chirho.to_string(),
            kind_id_chirho: AssetKindIdChirho("tok-chirho".to_string()),
        },
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("11".repeat(32))),
        delta_chirho,
        amount_chirho,
        post_chirho: LegPostStateChirho {
            credits_total_chirho: 0,
            debits_total_chirho: 0,
            held_chirho: 0,
        },
        counterpart_chirho: None,
    }
}

fn record_chirho(
    seq_chirho: u64,
    op_chirho: LedgerOpChirho,
    legs_chirho: Vec<LedgerLegChirho>,
) -> LedgerRecordChirho {
    LedgerRecordChirho {
        schema_chirho: LEDGER_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        format_version_chirho: 1,
        seq_chirho,
        prev_chirho: DigestChirho("00".repeat(32)),
        epoch_chirho: 1,
        hlc_chirho: HlcChirho {
            physical_ms_chirho: seq_chirho,
            logical_chirho: 0,
        },
        legs_chirho,
        op_chirho,
        idempotency_key_chirho: format!("idem-snap-{seq_chirho}"),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
        anchor_chirho: None,
        sig_chirho: "test-sig-chirho".to_string(),
        key_id_chirho: "test-key-chirho".to_string(),
    }
}

fn domain_chirho() -> ConservationDomainIdChirho {
    ConservationDomainIdChirho::new_chirho("mg-demo-chirho", "cluster-demo-chirho")
}

fn head_chirho(count_chirho: u64) -> ConservationHeadCoordinateChirho {
    ConservationHeadCoordinateChirho {
        epoch_chirho: 1,
        checkpoint_digest_chirho: DigestChirho("ee".repeat(32)),
        covered_record_count_chirho: count_chirho,
    }
}

/// mint 700 → alice; transfer alice→bob 200; burn 100 from alice. Leg-path nets (400 + 200)
/// must equal op-path supply (700 − 100) and the REAL checker must report GREEN.
fn mint_transfer_burn_chirho() -> Vec<LedgerRecordChirho> {
    vec![
        record_chirho(
            1,
            LedgerOpChirho::MintChirho {
                authority_evidence_chirho: DigestChirho("aa".repeat(32)),
            },
            vec![leg_chirho(
                "alice-chirho",
                LegDeltaChirho::CreditChirho,
                700,
            )],
        ),
        record_chirho(
            2,
            LedgerOpChirho::TransferChirho,
            vec![
                leg_chirho("alice-chirho", LegDeltaChirho::DebitChirho, 200),
                leg_chirho("bob-chirho", LegDeltaChirho::CreditChirho, 200),
            ],
        ),
        record_chirho(
            3,
            LedgerOpChirho::BurnChirho {
                authority_evidence_chirho: DigestChirho("bb".repeat(32)),
            },
            vec![leg_chirho("alice-chirho", LegDeltaChirho::DebitChirho, 100)],
        ),
    ]
}

#[test]
fn two_path_derivation_is_green_through_the_real_checker_chirho() {
    let snapshot_chirho = derive_conservation_snapshot_chirho(
        &mint_transfer_burn_chirho(),
        domain_chirho(),
        head_chirho(3),
    )
    .unwrap();
    assert_eq!(snapshot_chirho.rollups_chirho.len(), 1);
    assert_eq!(snapshot_chirho.rollups_chirho[0].account_net_chirho, 600);
    assert_eq!(snapshot_chirho.rollups_chirho[0].local_supply_chirho, 600);
    assert_eq!(snapshot_chirho.global_supplies_chirho.len(), 1);
    assert_eq!(snapshot_chirho.global_supplies_chirho[0].supply_chirho, 600);
    let evidence_chirho =
        run_conservation_monitor_once_chirho(&FixedSnapshotPortChirho { snapshot_chirho }).unwrap();
    assert_eq!(evidence_chirho.domain_kind_rollups_checked_chirho, 1);
    assert_eq!(evidence_chirho.global_supplies_checked_chirho, 1);
}

#[test]
fn a_doctored_leg_fires_the_real_drift_detector_chirho() {
    let mut records_chirho = mint_transfer_burn_chirho();
    // Bob's transfer credit grows to 250 while alice still loses 200 — the leg path now says
    // 650 against the op path's 600, exactly the doctored-walk shape the monitor exists for.
    records_chirho[1].legs_chirho[1].amount_chirho = 250;
    let snapshot_chirho =
        derive_conservation_snapshot_chirho(&records_chirho, domain_chirho(), head_chirho(3))
            .unwrap();
    let failure_chirho =
        run_conservation_monitor_once_chirho(&FixedSnapshotPortChirho { snapshot_chirho })
            .unwrap_err();
    match failure_chirho {
        ConservationMonitorFailureChirho::IncidentChirho(incident_chirho) => assert!(matches!(
            *incident_chirho.kind_chirho,
            ConservationIncidentKindChirho::DomainDriftChirho { .. }
                | ConservationIncidentKindChirho::GlobalKindDriftChirho { .. }
        )),
        other_chirho => panic!("expected a drift incident, got {other_chirho:?}"),
    }
}

#[test]
fn release_without_hold_refuses_typed_chirho() {
    let records_chirho = vec![record_chirho(
        7,
        LedgerOpChirho::TransferChirho,
        vec![leg_chirho("alice-chirho", LegDeltaChirho::ReleaseChirho, 5)],
    )];
    assert_eq!(
        derive_conservation_snapshot_chirho(&records_chirho, domain_chirho(), head_chirho(1))
            .unwrap_err(),
        SnapshotDeriveErrorChirho::LegFoldRefusedChirho { seq_chirho: 7 }
    );
}

#[test]
fn burn_exceeding_mint_refuses_typed_chirho() {
    // Synthetic non-admitted history (bob's credit arrives via a bare transfer leg so his net
    // stays >= 0) to isolate the negative-supply arm: mint 100, burn 200.
    let records_chirho = vec![
        record_chirho(
            1,
            LedgerOpChirho::MintChirho {
                authority_evidence_chirho: DigestChirho("aa".repeat(32)),
            },
            vec![leg_chirho(
                "alice-chirho",
                LegDeltaChirho::CreditChirho,
                100,
            )],
        ),
        record_chirho(
            2,
            LedgerOpChirho::TransferChirho,
            vec![leg_chirho("bob-chirho", LegDeltaChirho::CreditChirho, 200)],
        ),
        record_chirho(
            3,
            LedgerOpChirho::BurnChirho {
                authority_evidence_chirho: DigestChirho("bb".repeat(32)),
            },
            vec![leg_chirho("bob-chirho", LegDeltaChirho::DebitChirho, 200)],
        ),
    ];
    assert_eq!(
        derive_conservation_snapshot_chirho(&records_chirho, domain_chirho(), head_chirho(3))
            .unwrap_err(),
        SnapshotDeriveErrorChirho::BurnExceedsMintChirho {
            kind_id_chirho: AssetKindIdChirho("tok-chirho".to_string()),
        }
    );
}

#[test]
fn empty_history_derives_an_empty_green_snapshot_chirho() {
    let snapshot_chirho =
        derive_conservation_snapshot_chirho(&[], domain_chirho(), head_chirho(0)).unwrap();
    assert!(snapshot_chirho.rollups_chirho.is_empty());
    assert!(snapshot_chirho.global_supplies_chirho.is_empty());
    let evidence_chirho =
        run_conservation_monitor_once_chirho(&FixedSnapshotPortChirho { snapshot_chirho }).unwrap();
    assert_eq!(evidence_chirho.work_items_checked_chirho, 0);
}
