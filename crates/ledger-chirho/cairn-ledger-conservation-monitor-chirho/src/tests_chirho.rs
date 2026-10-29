// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho, MoneyGroupIdChirho};

use crate::checker_chirho::check_conservation_snapshot_chirho;
use crate::*;

fn money_group_chirho(name_chirho: &str) -> MoneyGroupIdChirho {
    MoneyGroupIdChirho(name_chirho.to_owned())
}

fn domain_for_group_chirho(
    money_group_chirho: &MoneyGroupIdChirho,
    cluster_chirho: &str,
) -> ConservationDomainIdChirho {
    ConservationDomainIdChirho {
        money_group_chirho: money_group_chirho.clone(),
        cluster_chirho: cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho(
            cluster_chirho.to_owned(),
        ),
    }
}

fn domain_chirho(name_chirho: &str) -> ConservationDomainIdChirho {
    domain_for_group_chirho(&money_group_chirho("money-group-chirho"), name_chirho)
}

fn head_chirho(covered_record_count_chirho: u64) -> ConservationHeadCoordinateChirho {
    ConservationHeadCoordinateChirho {
        epoch_chirho: 7,
        checkpoint_digest_chirho: DigestChirho(format!(
            "checkpoint-{covered_record_count_chirho}-chirho"
        )),
        covered_record_count_chirho,
    }
}

fn rollup_chirho(
    domain_chirho: ConservationDomainIdChirho,
    account_net_chirho: u128,
    local_supply_chirho: u128,
) -> DomainKindConservationRollupChirho {
    rollup_for_kind_chirho(
        domain_chirho,
        "credits-chirho",
        account_net_chirho,
        local_supply_chirho,
    )
}

fn rollup_for_kind_chirho(
    domain_chirho: ConservationDomainIdChirho,
    kind_id_chirho: &str,
    account_net_chirho: u128,
    local_supply_chirho: u128,
) -> DomainKindConservationRollupChirho {
    DomainKindConservationRollupChirho {
        domain_chirho,
        kind_id_chirho: AssetKindIdChirho(kind_id_chirho.to_owned()),
        account_net_chirho,
        local_supply_chirho,
    }
}

fn global_supply_for_group_chirho(
    money_group_chirho: MoneyGroupIdChirho,
    kind_id_chirho: &str,
    supply_chirho: u128,
) -> GlobalKindSupplyChirho {
    GlobalKindSupplyChirho {
        money_group_chirho,
        kind_id_chirho: AssetKindIdChirho(kind_id_chirho.to_owned()),
        supply_chirho,
    }
}

fn global_supply_chirho(kind_id_chirho: &str, supply_chirho: u128) -> GlobalKindSupplyChirho {
    global_supply_for_group_chirho(
        money_group_chirho("money-group-chirho"),
        kind_id_chirho,
        supply_chirho,
    )
}

fn snapshot_chirho(
    covered_record_count_chirho: u64,
    rollups_chirho: Vec<DomainKindConservationRollupChirho>,
    global_supplies_chirho: Vec<GlobalKindSupplyChirho>,
) -> HeadConsistentConservationSnapshotChirho {
    HeadConsistentConservationSnapshotChirho {
        head_chirho: head_chirho(covered_record_count_chirho),
        rollups_chirho,
        global_supplies_chirho,
    }
}

#[test]
fn internal_domain_is_green_chirho() {
    let green_snapshot_chirho = snapshot_chirho(
        2,
        vec![rollup_chirho(domain_chirho("a-chirho"), 100, 100)],
        vec![global_supply_chirho("credits-chirho", 100)],
    );

    let green_chirho = check_conservation_snapshot_chirho(&green_snapshot_chirho).unwrap();
    assert_eq!(green_chirho.money_group_kind_scopes_checked_chirho, 1);
    assert_eq!(green_chirho.domain_kind_rollups_checked_chirho, 1);
    assert_eq!(green_chirho.global_supplies_checked_chirho, 1);
    assert_eq!(green_chirho.work_items_checked_chirho, 2);
}

#[test]
fn stable_asset_kinds_are_reconciled_independently_chirho() {
    let domain_chirho = domain_chirho("a-chirho");
    let snapshot_chirho = snapshot_chirho(
        4,
        vec![
            rollup_for_kind_chirho(domain_chirho.clone(), "credits-chirho", 100, 100),
            rollup_for_kind_chirho(domain_chirho, "tokens-chirho", 40, 40),
        ],
        vec![
            global_supply_chirho("credits-chirho", 100),
            global_supply_chirho("tokens-chirho", 40),
        ],
    );

    let green_chirho = check_conservation_snapshot_chirho(&snapshot_chirho).unwrap();
    assert_eq!(green_chirho.money_group_kind_scopes_checked_chirho, 2);
    assert_eq!(green_chirho.domain_kind_rollups_checked_chirho, 2);
}

fn legacy_pair_adjusted_equation_chirho(
    account_net_chirho: u128,
    local_supply_chirho: u128,
    long_chirho: u128,
    short_chirho: u128,
) -> bool {
    account_net_chirho.checked_add(short_chirho) == local_supply_chirho.checked_add(long_chirho)
}

#[test]
fn reciprocal_positions_can_never_excuse_domain_drift_chirho() {
    assert!(legacy_pair_adjusted_equation_chirho(110, 100, 10, 0));
    assert!(legacy_pair_adjusted_equation_chirho(90, 100, 0, 10));

    let snapshot_chirho = snapshot_chirho(
        20,
        vec![
            rollup_chirho(domain_chirho("a-chirho"), 110, 100),
            rollup_chirho(domain_chirho("b-chirho"), 90, 100),
        ],
        vec![global_supply_chirho("credits-chirho", 200)],
    );

    assert!(matches!(
        *check_conservation_snapshot_chirho(&snapshot_chirho)
            .unwrap_err()
            .kind_chirho,
        ConservationIncidentKindChirho::DomainDriftChirho { .. }
    ));
}

#[test]
fn dropped_credit_is_a_named_domain_incident_chirho() {
    let domain_chirho = domain_chirho("a-chirho");
    let snapshot_chirho = snapshot_chirho(
        30,
        vec![rollup_chirho(domain_chirho.clone(), 99, 100)],
        vec![global_supply_chirho("credits-chirho", 100)],
    );

    let incident_chirho = check_conservation_snapshot_chirho(&snapshot_chirho).unwrap_err();
    assert_eq!(incident_chirho.head_chirho, snapshot_chirho.head_chirho);
    assert!(matches!(
        *incident_chirho.kind_chirho,
        ConservationIncidentKindChirho::DomainDriftChirho {
            domain_chirho: observed_domain_chirho,
            account_net_chirho: 99,
            local_supply_chirho: 100,
            ..
        } if observed_domain_chirho == domain_chirho
    ));
}

#[test]
fn offsetting_domain_drifts_cannot_hide_behind_global_green_chirho() {
    let snapshot_chirho = snapshot_chirho(
        40,
        vec![
            rollup_chirho(domain_chirho("a-chirho"), 90, 100),
            rollup_chirho(domain_chirho("b-chirho"), 110, 100),
        ],
        vec![global_supply_chirho("credits-chirho", 200)],
    );

    assert!(matches!(
        *check_conservation_snapshot_chirho(&snapshot_chirho)
            .unwrap_err()
            .kind_chirho,
        ConservationIncidentKindChirho::DomainDriftChirho { .. }
    ));
}

#[test]
fn independent_issuer_supply_catches_balanced_local_projection_drift_chirho() {
    let money_group_chirho = money_group_chirho("money-group-chirho");
    let snapshot_chirho = snapshot_chirho(
        50,
        vec![
            rollup_chirho(
                domain_for_group_chirho(&money_group_chirho, "a-chirho"),
                60,
                60,
            ),
            rollup_chirho(
                domain_for_group_chirho(&money_group_chirho, "b-chirho"),
                40,
                40,
            ),
        ],
        vec![global_supply_for_group_chirho(
            money_group_chirho.clone(),
            "credits-chirho",
            99,
        )],
    );

    assert!(matches!(
        *check_conservation_snapshot_chirho(&snapshot_chirho)
            .unwrap_err()
            .kind_chirho,
        ConservationIncidentKindChirho::GlobalKindDriftChirho {
            money_group_chirho: observed_money_group_chirho,
            account_net_chirho: 100,
            supply_chirho: 99,
            ..
        } if observed_money_group_chirho == money_group_chirho
    ));
}

#[test]
fn equal_kind_labels_under_distinct_money_groups_never_merge_chirho() {
    let first_group_chirho = money_group_chirho("first-money-group-chirho");
    let second_group_chirho = money_group_chirho("second-money-group-chirho");
    let green_snapshot_chirho = snapshot_chirho(
        51,
        vec![
            rollup_chirho(
                domain_for_group_chirho(&first_group_chirho, "a-chirho"),
                100,
                100,
            ),
            rollup_chirho(
                domain_for_group_chirho(&second_group_chirho, "b-chirho"),
                40,
                40,
            ),
        ],
        vec![
            global_supply_for_group_chirho(first_group_chirho, "credits-chirho", 100),
            global_supply_for_group_chirho(second_group_chirho, "credits-chirho", 40),
        ],
    );

    let green_chirho = check_conservation_snapshot_chirho(&green_snapshot_chirho).unwrap();
    assert_eq!(green_chirho.money_group_kind_scopes_checked_chirho, 2);

    let cross_root_offset_chirho = snapshot_chirho(
        52,
        vec![
            rollup_chirho(
                domain_for_group_chirho(
                    &money_group_chirho("first-money-group-chirho"),
                    "a-chirho",
                ),
                100,
                100,
            ),
            rollup_chirho(
                domain_for_group_chirho(
                    &money_group_chirho("second-money-group-chirho"),
                    "b-chirho",
                ),
                40,
                40,
            ),
        ],
        vec![
            global_supply_for_group_chirho(
                money_group_chirho("first-money-group-chirho"),
                "credits-chirho",
                90,
            ),
            global_supply_for_group_chirho(
                money_group_chirho("second-money-group-chirho"),
                "credits-chirho",
                50,
            ),
        ],
    );
    assert!(matches!(
        *check_conservation_snapshot_chirho(&cross_root_offset_chirho)
            .unwrap_err()
            .kind_chirho,
        ConservationIncidentKindChirho::GlobalKindDriftChirho { .. }
    ));
}

#[test]
fn global_supply_coverage_is_bidirectional_and_duplicate_safe_chirho() {
    let missing_supply_chirho = snapshot_chirho(
        53,
        vec![rollup_chirho(domain_chirho("a-chirho"), 100, 100)],
        vec![],
    );
    assert!(matches!(
        *check_conservation_snapshot_chirho(&missing_supply_chirho)
            .unwrap_err()
            .kind_chirho,
        ConservationIncidentKindChirho::MissingGlobalKindSupplyChirho { .. }
    ));

    let supply_without_domain_chirho = snapshot_chirho(
        54,
        vec![],
        vec![global_supply_chirho("credits-chirho", 100)],
    );
    assert!(matches!(
        *check_conservation_snapshot_chirho(&supply_without_domain_chirho)
            .unwrap_err()
            .kind_chirho,
        ConservationIncidentKindChirho::GlobalSupplyWithoutDomainRollupChirho { .. }
    ));

    let supply_chirho = global_supply_chirho("credits-chirho", 100);
    let duplicate_supply_chirho = snapshot_chirho(
        55,
        vec![rollup_chirho(domain_chirho("a-chirho"), 100, 100)],
        vec![supply_chirho.clone(), supply_chirho],
    );
    assert!(matches!(
        *check_conservation_snapshot_chirho(&duplicate_supply_chirho)
            .unwrap_err()
            .kind_chirho,
        ConservationIncidentKindChirho::DuplicateGlobalKindSupplyChirho { .. }
    ));
}

#[test]
fn duplicate_rollup_and_checked_overflow_fail_closed_chirho() {
    let duplicate_chirho = rollup_chirho(domain_chirho("a-chirho"), 100, 100);
    let duplicate_snapshot_chirho = snapshot_chirho(
        60,
        vec![duplicate_chirho.clone(), duplicate_chirho],
        vec![global_supply_chirho("credits-chirho", 100)],
    );
    assert!(matches!(
        *check_conservation_snapshot_chirho(&duplicate_snapshot_chirho)
            .unwrap_err()
            .kind_chirho,
        ConservationIncidentKindChirho::DuplicateDomainKindRollupChirho { .. }
    ));

    let overflow_snapshot_chirho = snapshot_chirho(
        61,
        vec![
            rollup_chirho(domain_chirho("a-chirho"), u128::MAX, u128::MAX),
            rollup_chirho(domain_chirho("b-chirho"), 1, 1),
        ],
        vec![global_supply_chirho("credits-chirho", u128::MAX)],
    );
    assert!(matches!(
        *check_conservation_snapshot_chirho(&overflow_snapshot_chirho)
            .unwrap_err()
            .kind_chirho,
        ConservationIncidentKindChirho::ArithmeticOverflowChirho
    ));
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FixturePortErrorChirho {
    UnavailableChirho,
}

struct FixturePortChirho {
    snapshot_chirho: Option<HeadConsistentConservationSnapshotChirho>,
}

impl VerifiedConservationSnapshotPortChirho for FixturePortChirho {
    type ErrorChirho = FixturePortErrorChirho;

    fn load_verified_head_consistent_snapshot_chirho(
        &self,
    ) -> Result<HeadConsistentConservationSnapshotChirho, Self::ErrorChirho> {
        self.snapshot_chirho
            .clone()
            .ok_or(FixturePortErrorChirho::UnavailableChirho)
    }
}

#[test]
fn unavailable_verified_snapshot_fails_closed_chirho() {
    let failure_chirho = run_conservation_monitor_once_chirho(&FixturePortChirho {
        snapshot_chirho: None,
    })
    .unwrap_err();
    assert_eq!(
        failure_chirho,
        ConservationMonitorFailureChirho::VerifiedSnapshotUnavailableChirho(
            FixturePortErrorChirho::UnavailableChirho
        )
    );
}

#[test]
fn scaling_twin_cost_depends_on_view_size_not_history_chirho() {
    let snapshot_chirho = |covered_record_count_chirho| {
        snapshot_chirho(
            covered_record_count_chirho,
            vec![rollup_chirho(domain_chirho("a-chirho"), 100, 100)],
            vec![global_supply_chirho("credits-chirho", 100)],
        )
    };
    let short_history_chirho = check_conservation_snapshot_chirho(&snapshot_chirho(2)).unwrap();
    let long_history_chirho = check_conservation_snapshot_chirho(&snapshot_chirho(2_000)).unwrap();

    assert_eq!(short_history_chirho.work_items_checked_chirho, 2);
    assert_eq!(
        short_history_chirho.work_items_checked_chirho,
        long_history_chirho.work_items_checked_chirho
    );
    assert_ne!(
        short_history_chirho.head_chirho.covered_record_count_chirho,
        long_history_chirho.head_chirho.covered_record_count_chirho
    );
}
