// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::testkind_loss_witness_chirho::{
    derive_resident_testkind_loss_witness_plan_chirho, ResidentTestkindLossWitnessOpenerModeChirho,
    ResidentTestkindLossWitnessPhaseChirho, ResidentTestkindLossWitnessRefusalChirho,
    ResidentTestkindLossWitnessRoleChirho,
};
use crate::tests_chirho::{
    authority_registry_chirho, test_kind_fence_tests_chirho::host_config_chirho,
};
use cairn_config_chirho::config_chirho::{
    LedgerHostConfigChirho, LedgerHostMemberConfigChirho, LedgerHostPostgresEffectConfigChirho,
    LedgerHostPostgresEffectPostureChirho, LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};

pub(crate) fn witness_config_chirho(test_kind_chirho: bool) -> LedgerHostConfigChirho {
    let mut config_chirho = host_config_chirho(test_kind_chirho);
    config_chirho.members_chirho = vec![
        LedgerHostMemberConfigChirho {
            owner_chirho: "payer-chirho".to_owned(),
            kind_id_chirho: "credits-chirho".to_owned(),
        },
        LedgerHostMemberConfigChirho {
            owner_chirho: "platform-chirho".to_owned(),
            kind_id_chirho: "credits-chirho".to_owned(),
        },
    ];
    config_chirho.postgres_effect_chirho = Some(LedgerHostPostgresEffectConfigChirho {
        schema_chirho: LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO.to_owned(),
        posture_chirho: LedgerHostPostgresEffectPostureChirho::LocalPhaseBChirho,
        connection_secret_chirho: "loss-witness-dsn-chirho".to_owned(),
        billing_kind_chirho: "credits-chirho".to_owned(),
    });
    config_chirho
}

#[test]
fn markerless_config_cannot_derive_a_loss_witness_plan_chirho() {
    assert_eq!(
        derive_resident_testkind_loss_witness_plan_chirho(
            &witness_config_chirho(false),
            &authority_registry_chirho(),
            ResidentTestkindLossWitnessOpenerModeChirho::MandatoryWitnessOrProductionChirho,
            false,
            false,
        )
        .unwrap(),
        None,
    );
}

#[test]
fn every_loss_witness_phase_token_round_trips_chirho() {
    let phases_chirho = [
        ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
        ResidentTestkindLossWitnessPhaseChirho::NodeLossChirho,
        ResidentTestkindLossWitnessPhaseChirho::RegionLossChirho,
        ResidentTestkindLossWitnessPhaseChirho::HealChirho,
        ResidentTestkindLossWitnessPhaseChirho::FailbackChirho,
    ];
    for phase_chirho in phases_chirho {
        assert_eq!(
            ResidentTestkindLossWitnessPhaseChirho::from_wire_token_chirho(
                phase_chirho.as_wire_token_chirho(),
            ),
            Some(phase_chirho),
        );
        assert_eq!(
            serde_json::to_value(phase_chirho).unwrap(),
            serde_json::json!(phase_chirho.as_wire_token_chirho()),
        );
    }
    assert_eq!(
        ResidentTestkindLossWitnessPhaseChirho::from_wire_token_chirho("invented-phase-chirho",),
        None,
    );
}

#[test]
fn marked_config_derives_one_balanced_actor_owned_transfer_chirho() {
    let plan_chirho = derive_resident_testkind_loss_witness_plan_chirho(
        &witness_config_chirho(true),
        &authority_registry_chirho(),
        ResidentTestkindLossWitnessOpenerModeChirho::MandatoryWitnessOrProductionChirho,
        false,
        false,
    )
    .unwrap()
    .expect("the valid test-kind config derives exactly one witness plan");
    let current_chirho = plan_chirho
        .append_request_chirho(
            ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
            ResidentTestkindLossWitnessRoleChirho::CurrentWriterChirho,
        )
        .unwrap();
    let deposed_chirho = plan_chirho
        .append_request_chirho(
            ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
            ResidentTestkindLossWitnessRoleChirho::DeposedSinkChirho,
        )
        .unwrap();

    assert_eq!(current_chirho.op_chirho, LedgerOpChirho::TransferChirho);
    assert_eq!(current_chirho.legs_chirho.len(), 2);
    assert_eq!(
        current_chirho.legs_chirho[0].delta_chirho,
        LegDeltaChirho::DebitChirho
    );
    assert_eq!(current_chirho.legs_chirho[0].amount_chirho, 1);
    assert_eq!(
        current_chirho.legs_chirho[0].account_chirho.owner_chirho,
        "payer-chirho"
    );
    assert_eq!(
        current_chirho.legs_chirho[1].delta_chirho,
        LegDeltaChirho::CreditChirho
    );
    assert_eq!(current_chirho.legs_chirho[1].amount_chirho, 1);
    assert_eq!(
        current_chirho.legs_chirho[1].account_chirho.owner_chirho,
        "platform-chirho"
    );
    assert!(current_chirho
        .legs_chirho
        .iter()
        .all(|leg_chirho| leg_chirho.kind_policy_ref_chirho.0 .0 == "11".repeat(32)));
    assert_eq!(current_chirho.provenance_chirho.unwrap().0, "44".repeat(32));
    assert_eq!(
        current_chirho.attribution_chirho,
        AttributionChirho::PlatformChirho
    );
    assert_ne!(
        current_chirho.idempotency_key_chirho, deposed_chirho.idempotency_key_chirho,
        "current and deposed attempts must never deduplicate each other"
    );
}

#[test]
fn marked_config_refuses_a_missing_provider_coordinate_chirho() {
    let mut config_chirho = witness_config_chirho(true);
    config_chirho.postgres_effect_chirho = None;
    assert_eq!(
        derive_resident_testkind_loss_witness_plan_chirho(
            &config_chirho,
            &authority_registry_chirho(),
            ResidentTestkindLossWitnessOpenerModeChirho::MandatoryWitnessOrProductionChirho,
            false,
            false,
        )
        .unwrap_err(),
        ResidentTestkindLossWitnessRefusalChirho::BillingKindConfigRefusedChirho,
    );
}

/// A config the dev bootstrap authors (exempt marker) opened through the dedicated normal-settlement
/// dev door's mode — single-node self-election, no compensation provider — derives NO loss-witness
/// plan. This is the derive-gate half of the exemption; the WIRING (that only the A+ door selects this
/// mode) is proven at the door level in the served-LLM dev E2E.
#[test]
fn exempt_marker_through_the_dev_opener_mode_derives_no_plan_chirho() {
    let mut config_chirho = witness_config_chirho(true);
    config_chirho
        .test_kind_chirho
        .as_mut()
        .expect("witness config is test-kind marked")
        .loss_witness_exempt_chirho = true;
    // Even with NO postgres coordinate, the exemption returns Ok(None) before the drill's
    // postgres requirement — a single-node served-money root has no drill to witness.
    config_chirho.postgres_effect_chirho = None;
    assert_eq!(
        derive_resident_testkind_loss_witness_plan_chirho(
            &config_chirho,
            &authority_registry_chirho(),
            ResidentTestkindLossWitnessOpenerModeChirho::NormalSettlementExemptionPermittedChirho,
            true,
            false,
        )
        .unwrap(),
        None,
    );
}

/// DEFENSE-IN-DEPTH for the derive gate: an exempt marker reaching the MANDATORY-witness opener mode
/// (every drill / shared-elector / compensation door) is a drill trying to suppress its own witness
/// and is refused by identity — regardless of the shape it presents. (The authoritative confinement
/// proof, that a real drill door selects this mode, is the door-level negative in the dev E2E.)
#[test]
fn exempt_marker_through_the_mandatory_opener_mode_is_refused_chirho() {
    let mut config_chirho = witness_config_chirho(true);
    config_chirho
        .test_kind_chirho
        .as_mut()
        .expect("witness config is test-kind marked")
        .loss_witness_exempt_chirho = true;
    // Even presenting the A+ SHAPE (single-node, no compensation), the mandatory mode refuses: the
    // exemption is confined by WHO opened the actor, not by the arguments that arrived.
    assert_eq!(
        derive_resident_testkind_loss_witness_plan_chirho(
            &config_chirho,
            &authority_registry_chirho(),
            ResidentTestkindLossWitnessOpenerModeChirho::MandatoryWitnessOrProductionChirho,
            true,
            false,
        )
        .unwrap_err(),
        ResidentTestkindLossWitnessRefusalChirho::DrillExemptionRefusedChirho,
    );
}

/// CONSISTENCY defense-in-depth: even in the exemption-permitted mode, an inconsistent shape (a shared
/// elector, or a compensation provider present) refuses. A drill that somehow reached the permitted
/// mode still cannot suppress its witness.
#[test]
fn exempt_marker_with_an_inconsistent_shape_is_refused_chirho() {
    let mut config_chirho = witness_config_chirho(true);
    config_chirho
        .test_kind_chirho
        .as_mut()
        .expect("witness config is test-kind marked")
        .loss_witness_exempt_chirho = true;
    // Shared-elector shape (not single-node) => refused, even in the permitted mode.
    assert_eq!(
        derive_resident_testkind_loss_witness_plan_chirho(
            &config_chirho,
            &authority_registry_chirho(),
            ResidentTestkindLossWitnessOpenerModeChirho::NormalSettlementExemptionPermittedChirho,
            false,
            false,
        )
        .unwrap_err(),
        ResidentTestkindLossWitnessRefusalChirho::DrillExemptionRefusedChirho,
    );
    // Compensation provider present => refused, even single-node in the permitted mode.
    assert_eq!(
        derive_resident_testkind_loss_witness_plan_chirho(
            &config_chirho,
            &authority_registry_chirho(),
            ResidentTestkindLossWitnessOpenerModeChirho::NormalSettlementExemptionPermittedChirho,
            true,
            true,
        )
        .unwrap_err(),
        ResidentTestkindLossWitnessRefusalChirho::DrillExemptionRefusedChirho,
    );
}
