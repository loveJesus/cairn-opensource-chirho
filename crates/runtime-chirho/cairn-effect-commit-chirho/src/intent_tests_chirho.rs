// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::intent_chirho::*;
use anyhow::Result;
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, AssetKindRefChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, HlcChirho};
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_undo_plan_chirho::plan_chirho::UndoDoorKeyChirho;

const DIGEST_A_CHIRHO: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B_CHIRHO: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C_CHIRHO: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DIGEST_D_CHIRHO: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const DIGEST_E_CHIRHO: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const DIGEST_F_CHIRHO: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

struct FakeIntentSignerChirho {
    root_chirho: &'static str,
}

impl EffectIntentSignerPortChirho for FakeIntentSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(signature_chirho(
            self.root_chirho,
            signed_content_line_chirho,
        ))
    }

    fn key_id_chirho(&self) -> String {
        format!("{}-key-chirho", self.root_chirho)
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == signature_chirho(self.root_chirho, signed_content_line_chirho)
    }
}

fn signature_chirho(root_chirho: &str, content_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(root_chirho.as_bytes());
    hasher_chirho.update(content_chirho.as_bytes());
    hasher_chirho.finalize().to_hex().to_string()
}

fn digest_chirho(value_chirho: &str) -> DigestChirho {
    DigestChirho(value_chirho.to_owned())
}

fn unsigned_intent_chirho() -> EffectIntentChirho {
    EffectIntentChirho {
        schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
        journal_cut_chirho: EffectIntentJournalCutChirho {
            journal_genesis_digest_chirho: digest_chirho(DIGEST_A_CHIRHO),
            tail_seq_chirho: 41,
            tail_record_digest_chirho: digest_chirho(DIGEST_B_CHIRHO),
            tail_hlc_chirho: HlcChirho {
                physical_ms_chirho: 1_750_000_000_000,
                logical_chirho: 7,
            },
        },
        contract_set_digest_chirho: digest_chirho(DIGEST_C_CHIRHO),
        door_chirho: serde_json::from_value::<UndoDoorKeyChirho>(serde_json::json!({
            "effect_node_chirho": DIGEST_D_CHIRHO,
            "capability_fingerprint_chirho": DIGEST_E_CHIRHO,
        }))
        .unwrap(),
        reversion_contract_digest_chirho: digest_chirho(DIGEST_F_CHIRHO),
        request_ref_chirho: digest_chirho(DIGEST_A_CHIRHO),
        request_context_ref_chirho: digest_chirho(DIGEST_B_CHIRHO),
        evidence_refs_chirho: vec![
            digest_chirho(DIGEST_C_CHIRHO),
            digest_chirho(DIGEST_D_CHIRHO),
        ],
        resolved_price_chirho: AssetOpChirho {
            amount_chirho: 125,
            kind_id_chirho: AssetKindIdChirho("billing-credit-chirho".to_owned()),
            kind_policy_ref_chirho: AssetKindRefChirho(digest_chirho(DIGEST_E_CHIRHO)),
            rounding_chirho: RoundingChirho::ExactChirho,
        },
        payer_account_chirho: LogIdChirho::new_chirho("user-7-chirho", "billing-credit-chirho"),
        effect_step_chirho: 3,
        attribution_chirho: AttributionChirho::CauserChirho {
            principal_chirho: "user-7-chirho".to_owned(),
        },
        original_effect_key_chirho: None,
        sig_chirho: String::new(),
        key_id_chirho: String::new(),
    }
}

fn signed_intent_chirho() -> EffectIntentChirho {
    sign_effect_intent_chirho(
        unsigned_intent_chirho(),
        &FakeIntentSignerChirho {
            root_chirho: "intent-root-chirho",
        },
    )
    .unwrap()
}

#[test]
fn canonical_signed_intent_roundtrips_and_verifies_under_only_its_root_chirho() {
    let intent_chirho = signed_intent_chirho();
    let line_chirho = canonical_effect_intent_line_chirho(&intent_chirho).unwrap();
    assert_eq!(
        effect_intent_signed_content_line_chirho(&intent_chirho).unwrap(),
        r#"{"schema_chirho":"effect-intent-v1-chirho","journal_cut_chirho":{"journal_genesis_digest_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tail_seq_chirho":41,"tail_record_digest_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tail_hlc_chirho":{"physical_ms_chirho":1750000000000,"logical_chirho":7}},"contract_set_digest_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","door_chirho":{"effect_node_chirho":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","capability_fingerprint_chirho":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},"reversion_contract_digest_chirho":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","request_ref_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request_context_ref_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidence_refs_chirho":["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],"resolved_price_chirho":{"amount_chirho":125,"kind_id_chirho":"billing-credit-chirho","kind_policy_ref_chirho":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","rounding_chirho":"exact-chirho"},"payer_account_chirho":{"owner_chirho":"user-7-chirho","kind_id_chirho":"billing-credit-chirho"},"effect_step_chirho":3,"attribution_chirho":{"causer":{"principal_chirho":"user-7-chirho"}},"sig_chirho":"","key_id_chirho":"intent-root-chirho-key-chirho"}"#
    );
    assert_eq!(
        parse_canonical_effect_intent_line_chirho(&line_chirho).unwrap(),
        intent_chirho
    );
    let verified_chirho = verify_effect_intent_line_chirho(
        &line_chirho,
        &FakeIntentSignerChirho {
            root_chirho: "intent-root-chirho",
        },
    )
    .unwrap();
    assert_eq!(verified_chirho.intent_chirho(), &intent_chirho);
    assert_eq!(
        parse_effect_intent_key_chirho(verified_chirho.key_chirho()).unwrap(),
        effect_intent_ref_chirho(&intent_chirho).unwrap()
    );
    assert!(matches!(
        verify_effect_intent_line_chirho(
            &line_chirho,
            &FakeIntentSignerChirho {
                root_chirho: "foreign-root-chirho",
            },
        ),
        Err(EffectIntentWireErrorChirho::SignatureUnverifiedChirho)
    ));
}

#[test]
fn full_signed_content_drives_k_but_detached_signature_does_not_chirho() {
    let first_chirho = signed_intent_chirho();
    let first_key_chirho = effect_intent_key_chirho(&first_chirho).unwrap();

    let mut restamped_chirho = unsigned_intent_chirho();
    restamped_chirho
        .journal_cut_chirho
        .tail_hlc_chirho
        .logical_chirho += 1;
    let restamped_chirho = sign_effect_intent_chirho(
        restamped_chirho,
        &FakeIntentSignerChirho {
            root_chirho: "intent-root-chirho",
        },
    )
    .unwrap();
    assert_ne!(
        first_key_chirho,
        effect_intent_key_chirho(&restamped_chirho).unwrap()
    );

    let mut altered_signature_chirho = first_chirho.clone();
    altered_signature_chirho.sig_chirho = DIGEST_F_CHIRHO.to_owned();
    assert_eq!(
        first_key_chirho,
        effect_intent_key_chirho(&altered_signature_chirho).unwrap()
    );
}

#[test]
fn reserved_namespace_recognizes_malformed_tails_but_parser_refuses_them_chirho() {
    for malformed_chirho in [
        EFFECT_INTENT_KEY_PREFIX_CHIRHO.to_owned(),
        format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}XYZ"),
        format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{}", "A".repeat(64)),
        format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{}", "a".repeat(63)),
    ] {
        assert!(is_reserved_effect_intent_key_chirho(&malformed_chirho));
        assert_eq!(
            parse_effect_intent_key_chirho(&malformed_chirho),
            Err(EffectIntentKeyErrorChirho::MalformedReservedChirho)
        );
    }
    assert!(!is_reserved_effect_intent_key_chirho("ordinary-key-chirho"));
    assert_eq!(
        parse_effect_intent_key_chirho("ordinary-key-chirho"),
        Err(EffectIntentKeyErrorChirho::NotReservedChirho)
    );
}

#[test]
fn compensation_coordinate_is_original_only_and_nests_deterministically_chirho() {
    let signer_chirho = FakeIntentSignerChirho {
        root_chirho: "intent-root-chirho",
    };
    let original_key_chirho = effect_intent_key_chirho(&signed_intent_chirho()).unwrap();
    let compensation_key_chirho = effect_compensation_key_chirho(&original_key_chirho).unwrap();
    let nested_key_chirho = effect_compensation_key_chirho(&compensation_key_chirho).unwrap();

    assert!(is_reserved_effect_compensation_key_chirho(
        &compensation_key_chirho
    ));
    assert!(parse_effect_compensation_key_chirho(&compensation_key_chirho).is_ok());
    assert_ne!(nested_key_chirho, compensation_key_chirho);
    assert!(parse_effect_compensation_key_chirho(&nested_key_chirho).is_ok());

    let mut first_event_chirho = unsigned_intent_chirho();
    first_event_chirho.original_effect_key_chirho = Some(original_key_chirho.clone());
    let mut second_event_chirho = first_event_chirho.clone();
    second_event_chirho.request_ref_chirho = DigestChirho(DIGEST_F_CHIRHO.to_owned());
    let first_event_chirho = sign_effect_intent_chirho(first_event_chirho, &signer_chirho).unwrap();
    let second_event_chirho =
        sign_effect_intent_chirho(second_event_chirho, &signer_chirho).unwrap();
    assert_ne!(
        effect_intent_key_chirho(&first_event_chirho).unwrap(),
        effect_intent_key_chirho(&second_event_chirho).unwrap()
    );
    assert_eq!(
        effect_compensation_key_chirho(
            first_event_chirho
                .original_effect_key_chirho
                .as_deref()
                .unwrap()
        )
        .unwrap(),
        effect_compensation_key_chirho(
            second_event_chirho
                .original_effect_key_chirho
                .as_deref()
                .unwrap()
        )
        .unwrap()
    );

    let mut nested_intent_chirho = unsigned_intent_chirho();
    nested_intent_chirho.original_effect_key_chirho = Some(compensation_key_chirho);
    assert!(sign_effect_intent_chirho(nested_intent_chirho, &signer_chirho).is_ok());
}

#[test]
fn compensation_namespace_recognizes_malformed_tails_but_parser_refuses_them_chirho() {
    let malformed_chirho = format!("{EFFECT_COMPENSATION_KEY_PREFIX_CHIRHO}XYZ");
    assert!(is_reserved_effect_compensation_key_chirho(
        &malformed_chirho
    ));
    assert_eq!(
        parse_effect_compensation_key_chirho(&malformed_chirho),
        Err(EffectCompensationKeyErrorChirho::MalformedReservedChirho)
    );
    assert_eq!(
        effect_compensation_key_chirho("ordinary-key-chirho"),
        Err(EffectCompensationKeyErrorChirho::InvalidOriginalEffectKeyChirho)
    );
}

#[test]
fn canonical_parser_refuses_malleability_chirho() {
    let line_chirho = canonical_effect_intent_line_chirho(&signed_intent_chirho()).unwrap();
    let without_schema_chirho = line_chirho
        .strip_prefix(r#"{"schema_chirho":"effect-intent-v1-chirho","#)
        .unwrap()
        .strip_suffix('}')
        .unwrap();
    let reordered_chirho =
        format!(r#"{{{without_schema_chirho},"schema_chirho":"effect-intent-v1-chirho"}}"#);
    assert!(matches!(
        parse_canonical_effect_intent_line_chirho(&reordered_chirho),
        Err(EffectIntentWireErrorChirho::NonCanonicalBytesChirho)
    ));
    assert!(parse_canonical_effect_intent_line_chirho(&format!(" {line_chirho}")).is_err());
    assert!(parse_canonical_effect_intent_line_chirho(&format!("{line_chirho}\n")).is_err());

    let unknown_chirho = line_chirho.replacen(
        r#"{"schema_chirho":"#,
        r#"{"unknown_chirho":1,"schema_chirho":"#,
        1,
    );
    assert!(parse_canonical_effect_intent_line_chirho(&unknown_chirho).is_err());
    let duplicate_chirho = line_chirho.replacen(
        r#"{"schema_chirho":"effect-intent-v1-chirho","#,
        r#"{"schema_chirho":"effect-intent-v1-chirho","schema_chirho":"effect-intent-v1-chirho","#,
        1,
    );
    assert!(parse_canonical_effect_intent_line_chirho(&duplicate_chirho).is_err());
}

#[test]
fn evidence_price_and_compensation_coordinates_fail_closed_chirho() {
    let signer_chirho = FakeIntentSignerChirho {
        root_chirho: "intent-root-chirho",
    };
    let mut unordered_chirho = unsigned_intent_chirho();
    unordered_chirho.evidence_refs_chirho.reverse();
    assert_eq!(
        sign_effect_intent_chirho(unordered_chirho, &signer_chirho),
        Err(EffectIntentWireErrorChirho::EvidenceOrderChirho)
    );

    let mut rounded_chirho = unsigned_intent_chirho();
    rounded_chirho.resolved_price_chirho.rounding_chirho = RoundingChirho::UpChirho;
    assert_eq!(
        sign_effect_intent_chirho(rounded_chirho, &signer_chirho),
        Err(EffectIntentWireErrorChirho::FixedPriceRoundingChirho)
    );

    let mut wrong_payer_kind_chirho = unsigned_intent_chirho();
    wrong_payer_kind_chirho.payer_account_chirho.kind_id_chirho =
        AssetKindIdChirho("other-kind-chirho".to_owned());
    assert!(matches!(
        sign_effect_intent_chirho(wrong_payer_kind_chirho, &signer_chirho),
        Err(EffectIntentWireErrorChirho::InvalidCoordinateChirho {
            field_chirho: "payer_account_chirho.kind_id_chirho"
        })
    ));

    let mut compensation_chirho = unsigned_intent_chirho();
    compensation_chirho.original_effect_key_chirho = Some("ordinary-key-chirho".to_owned());
    assert!(matches!(
        sign_effect_intent_chirho(compensation_chirho, &signer_chirho),
        Err(EffectIntentWireErrorChirho::InvalidCoordinateChirho {
            field_chirho: "original_effect_key_chirho"
        })
    ));
}

#[test]
fn crate_dependency_and_ambient_authority_guards_hold_chirho() {
    let cargo_chirho = include_str!("../Cargo.toml");
    for forbidden_chirho in [
        "cairn-ledger-read-model-chirho",
        "cairn-chirho =",
        "tokio",
        "reqwest",
        "ureq",
    ] {
        assert!(
            !cargo_chirho.contains(forbidden_chirho),
            "effect-commit leaf gained forbidden dependency {forbidden_chirho}"
        );
    }
    for (file_chirho, source_chirho) in [
        ("intent_chirho.rs", include_str!("intent_chirho.rs")),
        (
            "compensation_chirho.rs",
            include_str!("compensation_chirho.rs"),
        ),
    ] {
        for forbidden_chirho in ["std::fs", "std::env", "env::var", "std::net"] {
            assert!(
                !source_chirho.contains(forbidden_chirho),
                "effect-commit leaf {file_chirho} gained ambient authority token {forbidden_chirho}"
            );
        }
    }
}
