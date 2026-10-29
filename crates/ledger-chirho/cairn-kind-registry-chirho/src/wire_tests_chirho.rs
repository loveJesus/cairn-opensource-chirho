// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Registry wire proofs: golden canonical bytes, parse↔reserialize identity, the malleability RED
//! family (these records parameterize money law — the J0a bar), sign-then-attach content shapes,
//! and the content-addressed policy-ref derivation golden.

use crate::record_chirho::{
    IdempotencyWindowPolicyChirho, KindPolicyBodyChirho, KindRegistryOpChirho,
    KindRegistryRecordChirho, MintAuthorityRecordChirho, KIND_REGISTRY_SCHEMA_V1_CHIRHO,
};
use crate::wire_chirho::{
    canonical_registry_line_chirho, chain_anchor_chirho, derive_policy_ref_chirho,
    issuer_signed_content_chirho, parse_canonical_registry_line_chirho,
    registry_signed_content_chirho, stored_registry_line_digest_chirho, RegistryWireErrorChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::AssetKindIdChirho;

fn sample_policy_chirho() -> KindPolicyBodyChirho {
    KindPolicyBodyChirho {
        unit_chirho: "usd-cent-chirho".to_owned(),
        precision_chirho: 2,
        mint_authority_chirho: MintAuthorityRecordChirho::PlatformPolicyChirho {
            max_supply_chirho: Some(1_000_000),
        },
        rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
        shard_attachment_chirho: "shard-a-chirho".to_owned(),
        settlement_owner_chirho: None,
        idempotency_window_chirho: None,
    }
}

fn sample_record_chirho() -> KindRegistryRecordChirho {
    KindRegistryRecordChirho {
        schema_chirho: KIND_REGISTRY_SCHEMA_V1_CHIRHO.to_owned(),
        seq_chirho: 0,
        prev_chirho: chain_anchor_chirho("cairn-kind-registry:cluster-alpha-chirho"),
        registry_id_chirho: "cairn-kind-registry:cluster-alpha-chirho".to_owned(),
        op_chirho: KindRegistryOpChirho::RegisterKindChirho {
            kind_id_chirho: AssetKindIdChirho("money-chirho".to_owned()),
            policy_chirho: sample_policy_chirho(),
        },
        issuer_chirho: "issuer-root-chirho".to_owned(),
        issuer_sig_chirho: "issuer-sig-fixture-chirho".to_owned(),
        registry_sig_chirho: "registry-sig-fixture-chirho".to_owned(),
        key_id_chirho: "registry-key-1-chirho".to_owned(),
    }
}

#[test]
fn canonical_line_roundtrips_byte_exact_chirho() {
    let record_chirho = sample_record_chirho();
    let line_chirho = canonical_registry_line_chirho(&record_chirho).unwrap();
    let parsed_chirho = parse_canonical_registry_line_chirho(&line_chirho).unwrap();
    assert_eq!(parsed_chirho, record_chirho);
    assert_eq!(
        canonical_registry_line_chirho(&parsed_chirho).unwrap(),
        line_chirho,
        "one logical record, one content identity"
    );
}

#[test]
fn malleability_family_refuses_chirho() {
    let line_chirho = canonical_registry_line_chirho(&sample_record_chirho()).unwrap();
    // Leading whitespace, trailing newline, trailing bytes: parse or byte-equality must refuse.
    for mutated_chirho in [
        format!(" {line_chirho}"),
        format!("{line_chirho}\n"),
        format!("{line_chirho}x"),
    ] {
        assert!(
            parse_canonical_registry_line_chirho(&mutated_chirho).is_err(),
            "mutated bytes must refuse: {mutated_chirho:.40}"
        );
    }
    // An unknown field is refused by deny_unknown_fields.
    let unknown_chirho = line_chirho.replacen(
        "\"schema_chirho\"",
        "\"operation_chirho\":\"mint\",\"schema_chirho\"",
        1,
    );
    assert!(matches!(
        parse_canonical_registry_line_chirho(&unknown_chirho),
        Err(RegistryWireErrorChirho::MalformedChirho { .. })
    ));
    // Field reorder parses as the same VALUE but is NOT canonical bytes — refused.
    let reordered_chirho = {
        let value_chirho: serde_json::Value = serde_json::from_str(&line_chirho).unwrap();
        let serde_json::Value::Object(map_chirho) = value_chirho else {
            panic!("record is an object")
        };
        let mut pairs_chirho: Vec<(String, serde_json::Value)> = map_chirho.into_iter().collect();
        pairs_chirho.reverse();
        let mut out_chirho = String::from("{");
        for (index_chirho, (key_chirho, val_chirho)) in pairs_chirho.iter().enumerate() {
            if index_chirho > 0 {
                out_chirho.push(',');
            }
            out_chirho.push_str(&format!(
                "{}:{}",
                serde_json::to_string(key_chirho).unwrap(),
                serde_json::to_string(val_chirho).unwrap()
            ));
        }
        out_chirho.push('}');
        out_chirho
    };
    assert!(
        parse_canonical_registry_line_chirho(&reordered_chirho).is_err(),
        "reordered fields are not canonical bytes"
    );
    // A wrong schema tag refuses even when everything else parses.
    let wrong_schema_chirho = line_chirho.replacen(
        KIND_REGISTRY_SCHEMA_V1_CHIRHO,
        "cairn-kind-registry-record-v9-chirho",
        1,
    );
    assert!(matches!(
        parse_canonical_registry_line_chirho(&wrong_schema_chirho),
        Err(RegistryWireErrorChirho::MalformedChirho { .. })
    ));
}

#[test]
fn sign_then_attach_contents_nest_chirho() {
    let record_chirho = sample_record_chirho();
    let issuer_content_chirho = issuer_signed_content_chirho(&record_chirho).unwrap();
    let registry_content_chirho = registry_signed_content_chirho(&record_chirho).unwrap();
    // The issuer signs with BOTH sigs empty; the registry signs with the issuer sig ATTACHED.
    assert!(issuer_content_chirho.contains("\"issuer_sig_chirho\":\"\""));
    assert!(issuer_content_chirho.contains("\"registry_sig_chirho\":\"\""));
    assert!(registry_content_chirho.contains("\"issuer_sig_chirho\":\"issuer-sig-fixture-chirho\""));
    assert!(registry_content_chirho.contains("\"registry_sig_chirho\":\"\""));
    assert_ne!(issuer_content_chirho, registry_content_chirho);
    // Neither signed content equals the stored line (both differ from the fully-attached record).
    let line_chirho = canonical_registry_line_chirho(&record_chirho).unwrap();
    assert_ne!(issuer_content_chirho, line_chirho);
    assert_ne!(registry_content_chirho, line_chirho);
}

#[test]
fn policy_ref_derivation_is_content_addressed_chirho() {
    let ref_a_chirho = derive_policy_ref_chirho(&sample_policy_chirho()).unwrap();
    let ref_b_chirho = derive_policy_ref_chirho(&sample_policy_chirho()).unwrap();
    assert_eq!(ref_a_chirho, ref_b_chirho, "same body, same ref — always");
    let mut amended_chirho = sample_policy_chirho();
    amended_chirho.mint_authority_chirho = MintAuthorityRecordChirho::PlatformPolicyChirho {
        max_supply_chirho: Some(500_000),
    };
    let ref_c_chirho = derive_policy_ref_chirho(&amended_chirho).unwrap();
    assert_ne!(
        ref_a_chirho, ref_c_chirho,
        "any policy change is a NEW ref (R5b immutability)"
    );
    assert_eq!(ref_a_chirho.0 .0.len(), 64, "blake3 hex digest shape");
}

#[test]
fn optional_idempotency_window_preserves_legacy_bytes_and_changes_bound_identity_chirho() {
    let legacy_chirho = sample_policy_chirho();
    let legacy_bytes_chirho = serde_json::to_string(&legacy_chirho).unwrap();
    const LEGACY_POLICY_BYTES_CHIRHO: &str = concat!(
        "{\"unit_chirho\":\"usd-cent-chirho\",\"precision_chirho\":2,",
        "\"mint_authority_chirho\":{\"platform-policy-chirho\":{",
        "\"max_supply_chirho\":1000000}},\"rounding_chirho\":",
        "\"nearest-ties-to-even-chirho\",\"shard_attachment_chirho\":",
        "\"shard-a-chirho\"}"
    );
    assert_eq!(
        legacy_bytes_chirho, LEGACY_POLICY_BYTES_CHIRHO,
        "None must retain the exact pre-CF3 policy bytes and therefore its content ref"
    );

    let mut bounded_chirho = legacy_chirho.clone();
    bounded_chirho.idempotency_window_chirho = Some(IdempotencyWindowPolicyChirho {
        idempotency_horizon_ms_chirho: 86_400_000,
        retry_finality_horizon_ms_chirho: 3_600_000,
    });
    let bounded_bytes_chirho = serde_json::to_string(&bounded_chirho).unwrap();
    let parsed_chirho: KindPolicyBodyChirho = serde_json::from_str(&bounded_bytes_chirho).unwrap();
    assert_eq!(parsed_chirho, bounded_chirho);
    assert_ne!(
        derive_policy_ref_chirho(&legacy_chirho).unwrap(),
        derive_policy_ref_chirho(&bounded_chirho).unwrap(),
        "activating the W-law is a content-addressed policy revision"
    );
}

#[test]
fn chain_anchor_is_domain_separated_per_registry_chirho() {
    let anchor_a_chirho = chain_anchor_chirho("cairn-kind-registry:cluster-alpha-chirho");
    let anchor_b_chirho = chain_anchor_chirho("cairn-kind-registry:cluster-beta-chirho");
    assert_ne!(
        anchor_a_chirho, anchor_b_chirho,
        "two registries can never splice each other's chains"
    );
    let line_chirho = canonical_registry_line_chirho(&sample_record_chirho()).unwrap();
    let digest_chirho = stored_registry_line_digest_chirho(&line_chirho);
    assert_eq!(digest_chirho.0.len(), 64);
    assert_ne!(digest_chirho, anchor_a_chirho);
}
