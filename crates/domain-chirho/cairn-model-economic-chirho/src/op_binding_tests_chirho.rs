// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! J0a shape/wire tests for the frozen ledger schema-v2 op binding (extracted split test file).

use super::*;

fn hash_chirho(text_chirho: &str) -> HashChirho {
    HashChirho(text_chirho.to_string())
}

fn local_fence_chirho() -> MoneyWriterAuthorityContextChirho {
    MoneyWriterAuthorityContextChirho::LocalFenceV1Chirho {
        stable_group_id_chirho: hash_chirho("group-chirho"),
        local_group_digest_chirho: hash_chirho("digest-chirho"),
        local_epoch_chirho: 3,
    }
}

/// A well-shaped binding for `op_kind_chirho`, filling exactly the fields the per-kind matrix
/// requires and no others.
fn binding_chirho(op_kind_chirho: OpKindChirho) -> OpBindingChirho {
    OpBindingChirho {
        op_id_chirho: hash_chirho("op-id-chirho"),
        op_digest_chirho: hash_chirho("op-digest-chirho"),
        intent_generation_chirho: 0,
        planned_body_digest_chirho: hash_chirho("plan-chirho"),
        op_kind_chirho,
        money_writer_authority_context_chirho: local_fence_chirho(),
        allowance_refs_chirho: vec![],
        origin_op_ref_chirho: op_kind_chirho
            .requires_origin_op_ref_chirho()
            .then(|| hash_chirho("origin-chirho")),
        provider_call_id_chirho: op_kind_chirho
            .requires_provider_call_id_chirho()
            .then(|| hash_chirho("call-id-chirho")),
        witness_refs_chirho: if op_kind_chirho.requires_witness_chirho() {
            vec![hash_chirho("witness-chirho")]
        } else {
            vec![]
        },
    }
}

const ALL_KINDS_CHIRHO: &[OpKindChirho] = &[
    OpKindChirho::ChargeChirho,
    OpKindChirho::ReserveHoldChirho,
    OpKindChirho::SettleHoldChirho,
    OpKindChirho::ReleaseHoldChirho,
    OpKindChirho::SuspenseChirho,
    OpKindChirho::RefundChirho,
    OpKindChirho::GrantCreditChirho,
    OpKindChirho::TopUpChirho,
    OpKindChirho::PayoutReserveChirho,
    OpKindChirho::PayoutCallAuthorizedChirho,
    OpKindChirho::PayoutSettleChirho,
    OpKindChirho::PayoutPreCallReleaseChirho,
    OpKindChirho::PayoutPostCallReleaseChirho,
    OpKindChirho::InstallAllowanceChirho,
    OpKindChirho::RealtimeReserveChirho,
    OpKindChirho::RealtimeSettleChirho,
    OpKindChirho::RealtimeReleaseChirho,
    OpKindChirho::OperatorTransferChirho,
    OpKindChirho::OperatorGrantChirho,
    OpKindChirho::IdentityGrantChirho,
    OpKindChirho::ConversionChirho,
];

#[test]
fn every_kind_has_a_well_shaped_binding_chirho() {
    for kind_chirho in ALL_KINDS_CHIRHO {
        assert_eq!(
            binding_chirho(*kind_chirho).validate_shape_chirho(),
            Ok(()),
            "kind {kind_chirho:?} should have a well-shaped default binding"
        );
    }
}

#[test]
fn provider_call_id_is_a_strict_biconditional_and_top_up_is_inbound_chirho() {
    // The OUTBOUND payout family requires provider_call_id; a non-payout kind carrying one fails.
    let mut charge_chirho = binding_chirho(OpKindChirho::ChargeChirho);
    charge_chirho.provider_call_id_chirho = Some(hash_chirho("smuggled-chirho"));
    assert_eq!(
        charge_chirho.validate_shape_chirho(),
        Err(OpBindingShapeErrorChirho::ProviderCallIdKindMismatchChirho)
    );

    let mut payout_chirho = binding_chirho(OpKindChirho::PayoutReserveChirho);
    payout_chirho.provider_call_id_chirho = None;
    assert_eq!(
        payout_chirho.validate_shape_chirho(),
        Err(OpBindingShapeErrorChirho::ProviderCallIdKindMismatchChirho)
    );

    // Top-up is INBOUND: it must NOT carry a provider_call_id (contract ruling), and it MUST carry
    // its global event witness.
    assert!(!OpKindChirho::TopUpChirho.requires_provider_call_id_chirho());
    assert!(OpKindChirho::TopUpChirho.requires_witness_chirho());
    let mut topup_chirho = binding_chirho(OpKindChirho::TopUpChirho);
    topup_chirho.provider_call_id_chirho = Some(hash_chirho("invented-chirho"));
    assert_eq!(
        topup_chirho.validate_shape_chirho(),
        Err(OpBindingShapeErrorChirho::ProviderCallIdKindMismatchChirho)
    );
}

#[test]
fn witness_presence_is_a_strict_per_kind_biconditional_chirho() {
    // Witness-bearing kinds (top-up, payout settle, payout post-call release) require ≥1 witness.
    for kind_chirho in [
        OpKindChirho::TopUpChirho,
        OpKindChirho::PayoutSettleChirho,
        OpKindChirho::PayoutPostCallReleaseChirho,
    ] {
        let mut broken_chirho = binding_chirho(kind_chirho);
        broken_chirho.witness_refs_chirho = vec![];
        assert_eq!(
            broken_chirho.validate_shape_chirho(),
            Err(OpBindingShapeErrorChirho::WitnessRefsKindMismatchChirho),
            "{kind_chirho:?} must require a witness"
        );
    }
    // Pre-result payout kinds and every non-provider kind must carry NO witness.
    for kind_chirho in [
        OpKindChirho::PayoutReserveChirho,
        OpKindChirho::PayoutCallAuthorizedChirho,
        OpKindChirho::PayoutPreCallReleaseChirho,
        OpKindChirho::ChargeChirho,
    ] {
        let mut broken_chirho = binding_chirho(kind_chirho);
        broken_chirho.witness_refs_chirho = vec![hash_chirho("stray-witness-chirho")];
        assert_eq!(
            broken_chirho.validate_shape_chirho(),
            Err(OpBindingShapeErrorChirho::WitnessRefsKindMismatchChirho),
            "{kind_chirho:?} must forbid a witness"
        );
    }
}

#[test]
fn origin_op_ref_is_a_strict_biconditional_including_the_payout_marker_chirho() {
    // The payout marker (call-authorized) transitions FROM the reserve and must bind its origin.
    assert!(OpKindChirho::PayoutCallAuthorizedChirho.requires_origin_op_ref_chirho());
    let mut marker_chirho = binding_chirho(OpKindChirho::PayoutCallAuthorizedChirho);
    marker_chirho.origin_op_ref_chirho = None;
    assert_eq!(
        marker_chirho.validate_shape_chirho(),
        Err(OpBindingShapeErrorChirho::OriginOpRefKindMismatchChirho)
    );

    let mut charge_chirho = binding_chirho(OpKindChirho::ChargeChirho);
    charge_chirho.origin_op_ref_chirho = Some(hash_chirho("unexpected-chirho"));
    assert_eq!(
        charge_chirho.validate_shape_chirho(),
        Err(OpBindingShapeErrorChirho::OriginOpRefKindMismatchChirho)
    );
}

#[test]
fn allowance_refs_are_spend_kind_only_chirho() {
    // A non-spend kind may not carry allowance consumption.
    let allowance_chirho = AllowanceRefChirho {
        scope_chirho: "app-chirho".to_string(),
        generation_chirho: 1,
        window_id_chirho: ALLOWANCE_WINDOW_LIFETIME_CHIRHO.to_string(),
    };
    for kind_chirho in [
        OpKindChirho::GrantCreditChirho,
        OpKindChirho::InstallAllowanceChirho,
        OpKindChirho::RefundChirho,
        OpKindChirho::PayoutSettleChirho,
    ] {
        let mut broken_chirho = binding_chirho(kind_chirho);
        broken_chirho.allowance_refs_chirho = vec![allowance_chirho.clone()];
        assert_eq!(
            broken_chirho.validate_shape_chirho(),
            Err(OpBindingShapeErrorChirho::AllowanceRefsOnNonSpendKindChirho),
            "{kind_chirho:?} must not carry allowance refs"
        );
    }
    // A spend kind MAY carry them.
    let mut charge_chirho = binding_chirho(OpKindChirho::ChargeChirho);
    charge_chirho.allowance_refs_chirho = vec![allowance_chirho];
    assert_eq!(charge_chirho.validate_shape_chirho(), Ok(()));
}

#[test]
fn a_non_local_fence_authority_context_is_never_shape_valid_chirho() {
    let mut charge_chirho = binding_chirho(OpKindChirho::ChargeChirho);
    charge_chirho.money_writer_authority_context_chirho =
        MoneyWriterAuthorityContextChirho::ElectedTermV1Chirho {
            stable_group_id_chirho: hash_chirho("group-chirho"),
            election_config_digest_chirho: hash_chirho("config-chirho"),
            term_chirho: 1,
            leader_chirho: "leader-chirho".to_string(),
            quorum_commit_certificate_ref_chirho: hash_chirho("cert-chirho"),
        };
    assert_eq!(
        charge_chirho.validate_shape_chirho(),
        Err(OpBindingShapeErrorChirho::NonLocalFenceAuthorityChirho)
    );
}

#[test]
fn v2_sub_objects_reject_unknown_fields_never_parse_and_drop_chirho() {
    // A well-formed binding round-trips.
    let json_chirho = serde_json::to_string(&binding_chirho(OpKindChirho::ChargeChirho)).unwrap();
    assert!(serde_json::from_str::<OpBindingChirho>(&json_chirho).is_ok());

    // An unknown top-level field on the binding is REJECTED (not silently dropped).
    let with_unknown_chirho = json_chirho.replacen('{', "{\"attacker_field_chirho\":1,", 1);
    assert!(serde_json::from_str::<OpBindingChirho>(&with_unknown_chirho).is_err());

    // An unknown NESTED field (inside the authority context) is REJECTED.
    let nested_unknown_chirho = json_chirho.replacen(
        "\"mode_chirho\"",
        "\"attacker_nested_chirho\":1,\"mode_chirho\"",
        1,
    );
    assert!(serde_json::from_str::<OpBindingChirho>(&nested_unknown_chirho).is_err());

    // An unknown field on an allowance ref is REJECTED.
    let allowance_json_chirho = serde_json::to_string(&AllowanceRefChirho {
        scope_chirho: "app-chirho".to_string(),
        generation_chirho: 1,
        window_id_chirho: ALLOWANCE_WINDOW_LIFETIME_CHIRHO.to_string(),
    })
    .unwrap()
    .replacen('{', "{\"extra_chirho\":1,", 1);
    assert!(serde_json::from_str::<AllowanceRefChirho>(&allowance_json_chirho).is_err());
}

#[test]
fn wire_labels_are_byte_stable_never_inferred_from_rust_spelling_chirho() {
    assert_eq!(LEDGER_ENTRY_SCHEMA_V2_CHIRHO, "ledger-entry-v2-chirho");
    // op_kind wire discriminants (the split payout release kinds included).
    assert_eq!(
        serde_json::to_string(&OpKindChirho::PayoutCallAuthorizedChirho).unwrap(),
        "\"payout-call-authorized\""
    );
    assert_eq!(
        serde_json::to_string(&OpKindChirho::PayoutPreCallReleaseChirho).unwrap(),
        "\"payout-pre-call-release\""
    );
    assert_eq!(
        serde_json::to_string(&OpKindChirho::PayoutPostCallReleaseChirho).unwrap(),
        "\"payout-post-call-release\""
    );
    assert_eq!(
        serde_json::to_string(&OpKindChirho::GrantCreditChirho).unwrap(),
        "\"grant-credit\""
    );
    // authority-mode wire discriminant.
    let json_chirho = serde_json::to_value(local_fence_chirho()).unwrap();
    assert_eq!(json_chirho["mode_chirho"], "local-fence-v1");
}
