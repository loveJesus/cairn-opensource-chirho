// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Vocabulary arms: hex/number newtype construction and round-trip, closed-enum wire tokens,
//! hard-gates-cannot-be-typed-true, and the ruling `UnresolvedChirho` refusal keyed by field.

use crate::error_chirho::{GeoGenesisRefusalChirho, GeoRulingFieldChirho};
use crate::gate_chirho::{GeoProductHardGatesClosedV1Chirho, ProductionMoneyGateChirho};
use crate::metadata_chirho::GeoBuildTargetChirho;
use crate::metadata_chirho::GeoProviderChirho;
use crate::ruling_chirho::{
    GeoCellAdvanceRulingChirho, GeoGenesisRulingSetV1Chirho, GeoGg6OrderingRulingChirho,
    GeoItem7ClosureChirho, GeoItem7DurabilityChirho, GeoItem7FailureSemanticsChirho,
    GeoItem7MembershipFreshnessChirho, GeoItem7ReadServingChirho, GeoItem7ReplicaCountChirho,
    GeoItem7RulingSetV1Chirho,
};
use crate::scalar_chirho::{
    GeoEd25519SignatureChirho, GeoGenesisInstanceIdChirho, GeoIpAddressChirho, GeoPortChirho,
    GeoRaftIdChirho, GeoUtcMinuteChirho, GEO_UTC_MINUTE_MAX_CHIRHO,
};

// --- hex newtypes ----------------------------------------------------------------------------

#[test]
fn hex_newtype_round_trips_through_wire_chirho() {
    let bytes_chirho = [7u8; 32];
    let id_chirho = GeoGenesisInstanceIdChirho::new_chirho(bytes_chirho).unwrap();
    let json_chirho = serde_json::to_string(&id_chirho).unwrap();
    assert_eq!(json_chirho, format!("\"{}\"", "07".repeat(32)));
    let back_chirho: GeoGenesisInstanceIdChirho = serde_json::from_str(&json_chirho).unwrap();
    assert_eq!(back_chirho, id_chirho);
    assert_eq!(back_chirho.as_bytes_chirho(), &bytes_chirho);
}

#[test]
fn hex_newtype_rejects_wrong_length_case_and_charset_chirho() {
    // Wrong length.
    assert_eq!(
        GeoGenesisInstanceIdChirho::from_hex_chirho(&"07".repeat(31)),
        Err(GeoGenesisRefusalChirho::HexEncodingChirho)
    );
    // Uppercase is not the canonical lowercase form.
    assert_eq!(
        GeoGenesisInstanceIdChirho::from_hex_chirho(&"AB".repeat(32)),
        Err(GeoGenesisRefusalChirho::HexEncodingChirho)
    );
    // Non-hex.
    assert_eq!(
        GeoGenesisInstanceIdChirho::from_hex_chirho(&"zz".repeat(32)),
        Err(GeoGenesisRefusalChirho::HexEncodingChirho)
    );
    // A 64-byte signature is a distinct length and codec.
    assert!(GeoEd25519SignatureChirho::from_hex_chirho(&"01".repeat(64)).is_ok());
    assert_eq!(
        GeoEd25519SignatureChirho::from_hex_chirho(&"01".repeat(32)),
        Err(GeoGenesisRefusalChirho::HexEncodingChirho)
    );
}

#[test]
fn all_zero_identity_refuses_by_distinct_reason_chirho() {
    assert_eq!(
        GeoGenesisInstanceIdChirho::new_chirho([0u8; 32]),
        Err(GeoGenesisRefusalChirho::AllZeroIdentityChirho)
    );
    // A non-identity 32-byte class (a signature-length is different, but a key permits zero bytes as a
    // format matter; only the CSPRNG identities reject zero).
    assert!(GeoGenesisInstanceIdChirho::new_chirho([1u8; 32]).is_ok());
}

// --- numeric newtypes ------------------------------------------------------------------------

#[test]
fn nonzero_numeric_newtypes_refuse_zero_by_distinct_reason_chirho() {
    assert_eq!(
        GeoRaftIdChirho::new_chirho(0),
        Err(GeoGenesisRefusalChirho::ZeroRaftIdChirho)
    );
    assert_eq!(
        GeoPortChirho::new_chirho(0),
        Err(GeoGenesisRefusalChirho::ZeroPortChirho)
    );
    assert!(GeoRaftIdChirho::new_chirho(1).is_ok());
    assert!(GeoPortChirho::new_chirho(443).is_ok());
}

#[test]
fn numeric_newtype_rejects_float_and_out_of_range_on_wire_chirho() {
    // A float is not an integer coordinate.
    assert!(serde_json::from_str::<GeoRaftIdChirho>("1.5").is_err());
    // Zero refuses on the wire too (construction validation runs in Deserialize).
    assert!(serde_json::from_str::<GeoRaftIdChirho>("0").is_err());
    // The coarse-time ceiling.
    assert_eq!(
        GeoUtcMinuteChirho::new_chirho(GEO_UTC_MINUTE_MAX_CHIRHO + 1),
        Err(GeoGenesisRefusalChirho::TimeOutOfRangeChirho)
    );
    assert!(GeoUtcMinuteChirho::new_chirho(GEO_UTC_MINUTE_MAX_CHIRHO).is_ok());
}

#[test]
fn ip_address_round_trips_as_numeric_octets_chirho() {
    let v4_chirho = GeoIpAddressChirho::Ipv4Chirho([10, 0, 0, 1]);
    let json_chirho = serde_json::to_string(&v4_chirho).unwrap();
    assert_eq!(json_chirho, "{\"ipv4_chirho\":[10,0,0,1]}");
    let back_chirho: GeoIpAddressChirho = serde_json::from_str(&json_chirho).unwrap();
    assert_eq!(back_chirho, v4_chirho);
    // No hostname/free-text variant exists.
    assert!(serde_json::from_str::<GeoIpAddressChirho>("{\"hostname_chirho\":\"a\"}").is_err());
}

// --- closed metadata enums -------------------------------------------------------------------

#[test]
fn closed_metadata_enum_wire_tokens_are_pinned_chirho() {
    assert_eq!(
        serde_json::to_string(&GeoProviderChirho::DigitalOceanChirho).unwrap(),
        "\"digital_ocean_chirho\""
    );
    assert_eq!(
        serde_json::to_string(&GeoBuildTargetChirho::Aarch64UnknownLinuxGnuChirho).unwrap(),
        "\"aarch64_unknown_linux_gnu_chirho\""
    );
    // An unreviewed provider label refuses; there is no Other(String) escape hatch.
    assert!(serde_json::from_str::<GeoProviderChirho>("\"linode_chirho\"").is_err());
}

// --- hard gates false by type ----------------------------------------------------------------

#[test]
fn hard_gate_cannot_be_typed_or_parsed_true_chirho() {
    // The only inhabitant parses.
    assert_eq!(
        serde_json::from_str::<ProductionMoneyGateChirho>("\"closed_chirho\"").unwrap(),
        ProductionMoneyGateChirho::ClosedChirho
    );
    // There is no open wire value.
    assert!(serde_json::from_str::<ProductionMoneyGateChirho>("\"open_chirho\"").is_err());
    assert!(serde_json::from_str::<ProductionMoneyGateChirho>("\"open\"").is_err());
    assert!(serde_json::from_str::<ProductionMoneyGateChirho>("true").is_err());

    // The whole hard-gate struct round-trips and its only value is all-closed.
    let gates_chirho = GeoProductHardGatesClosedV1Chirho::all_closed_chirho();
    let json_chirho = serde_json::to_string(&gates_chirho).unwrap();
    let back_chirho: GeoProductHardGatesClosedV1Chirho =
        serde_json::from_str(&json_chirho).unwrap();
    assert_eq!(back_chirho, gates_chirho);
    // An open field refuses.
    let open_chirho = json_chirho.replace("\"closed_chirho\"", "\"open_chirho\"");
    assert!(serde_json::from_str::<GeoProductHardGatesClosedV1Chirho>(&open_chirho).is_err());
}

#[test]
fn record_struct_denies_unknown_and_duplicate_fields_chirho() {
    let gates_chirho = GeoProductHardGatesClosedV1Chirho::all_closed_chirho();
    let json_chirho = serde_json::to_string(&gates_chirho).unwrap();
    // Unknown field.
    let with_unknown_chirho = json_chirho.replace("{", "{\"unexpected_chirho\":\"closed_chirho\",");
    assert!(
        serde_json::from_str::<GeoProductHardGatesClosedV1Chirho>(&with_unknown_chirho).is_err()
    );
    // Duplicate key (serde derive rejects duplicate struct fields).
    let with_dup_chirho =
        json_chirho.replace("{", "{\"production_money_chirho\":\"closed_chirho\",");
    assert!(serde_json::from_str::<GeoProductHardGatesClosedV1Chirho>(&with_dup_chirho).is_err());
}

// --- ruling representation + unresolved refusal ----------------------------------------------

fn resolved_item7_chirho() -> GeoItem7RulingSetV1Chirho {
    GeoItem7RulingSetV1Chirho {
        replica_count_chirho: GeoItem7ReplicaCountChirho::N2ZoneChirho,
        membership_freshness_chirho: GeoItem7MembershipFreshnessChirho::JoinedExactViewChirho,
        durability_chirho: GeoItem7DurabilityChirho::NativeDurabilityChirho,
        closure_chirho: GeoItem7ClosureChirho::ManifestedPrefixClosureChirho,
        failure_semantics_chirho: GeoItem7FailureSemanticsChirho::PrepareCommitFinalizeChirho,
        read_serving_chirho: GeoItem7ReadServingChirho::ReceiptGatedServingChirho,
    }
}

fn resolved_ruling_set_chirho() -> GeoGenesisRulingSetV1Chirho {
    GeoGenesisRulingSetV1Chirho {
        cell_advance_chirho: GeoCellAdvanceRulingChirho::WinnerForkWitnessOnDemandChirho,
        item7_chirho: resolved_item7_chirho(),
        gg6_ordering_chirho: GeoGg6OrderingRulingChirho::WiringReadyThenHostedAcceptedChirho,
    }
}

#[test]
fn resolved_ruling_set_validates_and_round_trips_chirho() {
    let ruling_chirho = resolved_ruling_set_chirho();
    ruling_chirho.validate_resolved_chirho().unwrap();
    let json_chirho = serde_json::to_string(&ruling_chirho).unwrap();
    let back_chirho: GeoGenesisRulingSetV1Chirho = serde_json::from_str(&json_chirho).unwrap();
    assert_eq!(back_chirho, ruling_chirho);
    // Unresolved is still a representable, parseable token (kept per ruling 5).
    assert_eq!(
        serde_json::to_string(&GeoCellAdvanceRulingChirho::UnresolvedChirho).unwrap(),
        "\"unresolved_chirho\""
    );
}

#[test]
fn unresolved_top_level_ruling_refuses_by_field_chirho() {
    let mut ruling_chirho = resolved_ruling_set_chirho();
    ruling_chirho.cell_advance_chirho = GeoCellAdvanceRulingChirho::UnresolvedChirho;
    assert_eq!(
        ruling_chirho.validate_resolved_chirho(),
        Err(GeoGenesisRefusalChirho::UnresolvedRulingChirho {
            field_chirho: GeoRulingFieldChirho::CellAdvanceChirho
        })
    );

    let mut ruling_chirho = resolved_ruling_set_chirho();
    ruling_chirho.gg6_ordering_chirho = GeoGg6OrderingRulingChirho::UnresolvedChirho;
    assert_eq!(
        ruling_chirho.validate_resolved_chirho(),
        Err(GeoGenesisRefusalChirho::UnresolvedRulingChirho {
            field_chirho: GeoRulingFieldChirho::Gg6OrderingChirho
        })
    );
}

#[test]
fn unresolved_item7_token_refuses_by_its_own_field_chirho() {
    let mut ruling_chirho = resolved_ruling_set_chirho();
    ruling_chirho.item7_chirho.durability_chirho = GeoItem7DurabilityChirho::UnresolvedChirho;
    assert_eq!(
        ruling_chirho.validate_resolved_chirho(),
        Err(GeoGenesisRefusalChirho::UnresolvedRulingChirho {
            field_chirho: GeoRulingFieldChirho::Item7DurabilityChirho
        })
    );

    let mut ruling_chirho = resolved_ruling_set_chirho();
    ruling_chirho.item7_chirho.read_serving_chirho = GeoItem7ReadServingChirho::UnresolvedChirho;
    assert_eq!(
        ruling_chirho.validate_resolved_chirho(),
        Err(GeoGenesisRefusalChirho::UnresolvedRulingChirho {
            field_chirho: GeoRulingFieldChirho::Item7ReadServingChirho
        })
    );
}
