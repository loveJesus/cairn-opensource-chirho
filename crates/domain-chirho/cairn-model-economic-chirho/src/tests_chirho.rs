// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::billing_contract_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_privacy_chirho::PrivateBlobRefChirho;
use std::collections::BTreeMap;

fn hash_chirho(hex_chirho: &str) -> HashChirho {
    HashChirho(hex_chirho.to_string())
}

fn assert_byte_exact_json_roundtrip_chirho<T>(line_chirho: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let record_chirho: T = serde_json::from_str(line_chirho).unwrap();
    assert_eq!(serde_json::to_string(&record_chirho).unwrap(), line_chirho);
}

fn billing_wire_hash_chirho(marker_chirho: char) -> HashChirho {
    HashChirho(marker_chirho.to_string().repeat(64))
}

fn billing_wire_tags_chirho() -> BillingTagsChirho {
    BillingTagsChirho {
        user_id_chirho: Some("caller-chirho".to_string()),
        app_id_chirho: Some("app-chirho".to_string()),
        run_id_chirho: Some(billing_wire_hash_chirho('c')),
        effect_id_chirho: Some("effect-chirho".to_string()),
    }
}

fn private_blob_ref_fixture_chirho(marker_chirho: char) -> PrivateBlobRefChirho {
    PrivateBlobRefChirho {
        ciphertext_chirho: HashChirho(marker_chirho.to_string().repeat(64)),
        key_id_chirho: format!("key-{marker_chirho}-chirho"),
        nonce_chirho: format!("nonce-{marker_chirho}-chirho"),
        mac_chirho: format!("mac-{marker_chirho}-chirho"),
        alg_chirho: "xchacha20poly1305+blake3-keyed-mac/v1".to_string(),
    }
}

fn billing_wire_usage_record_chirho() -> BillingUsageRecordChirho {
    BillingUsageRecordChirho {
        seq_chirho: 3,
        schema_chirho: BILLING_USAGE_RECORD_SCHEMA_CHIRHO.to_string(),
        app_chirho: "app-chirho".to_string(),
        effect_chirho: "effect-chirho".to_string(),
        caller_chirho: "caller-chirho".to_string(),
        payer_chirho: "payer-chirho".to_string(),
        payer_kind_chirho: BillingPayerKindChirho::UserChirho,
        provider_chirho: "provider-chirho".to_string(),
        price_chirho: 17,
        price_book_chirho: billing_wire_hash_chirho('a'),
        billing_policy_chirho: Some(billing_wire_hash_chirho('b')),
        mode_chirho: BillingPolicyModeChirho::UserPaysChirho,
        ledger_seq_chirho: 4,
        cache_hit_chirho: false,
        nway_settlement_chirho: false,
        external_provider_chirho: None,
        external_cost_token_chirho: 0,
        platform_fee_chirho: 0,
        owner_margin_chirho: 0,
        credit_hold_chirho: None,
        billing_tags_chirho: billing_wire_tags_chirho(),
        at_ms_chirho: 99,
        sig_chirho: "sig-chirho".to_string(),
    }
}

#[test]
fn billing_policy_selection_uses_family_sequence_not_wall_clock_chirho() {
    let app_chirho = "seqbilling";
    let records_chirho = vec![
        BillingPolicyRecordChirho {
            seq_chirho: 0,
            schema_chirho: BILLING_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: "owner/seqbilling".to_string(),
            billing_policy_chirho: HashChirho("a".repeat(64)),
            previous_chirho: None,
            at_ms_chirho: u64::MAX,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: "first".to_string(),
        },
        BillingPolicyRecordChirho {
            seq_chirho: 1,
            schema_chirho: BILLING_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: "owner/seqbilling".to_string(),
            billing_policy_chirho: HashChirho("b".repeat(64)),
            previous_chirho: Some(HashChirho("a".repeat(64))),
            at_ms_chirho: 1,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: "second".to_string(),
        },
    ];
    assert_eq!(
        billing_contract_chirho::latest_billing_policy_record_by_seq_chirho(
            &records_chirho,
            app_chirho,
        )
        .unwrap()
        .seq_chirho,
        1
    );
}

fn assert_billing_message_bytes_chirho(
    label_chirho: &str,
    actual_chirho: Vec<u8>,
    expected_chirho: &[u8],
) {
    assert_eq!(
        std::str::from_utf8(&actual_chirho).unwrap(),
        std::str::from_utf8(expected_chirho).unwrap(),
        "{label_chirho}"
    );
}

#[test]
fn price_book_record_omits_legacy_empty_schema_chirho() {
    let record_chirho = PriceBookRecordChirho {
        seq_chirho: 7,
        schema_chirho: String::new(),
        app_chirho: "priced-app-chirho".to_string(),
        owner_principal_chirho: "owner/price-chirho".to_string(),
        price_book_chirho: hash_chirho(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        previous_chirho: None,
        at_ms_chirho: 11,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: "sig-chirho".to_string(),
    };
    let value_chirho = serde_json::to_value(record_chirho).unwrap();
    assert!(value_chirho.get("schema_chirho").is_none());
}

#[test]
fn price_book_serialization_stays_stable_chirho() {
    let mut effect_prices_chirho = BTreeMap::new();
    effect_prices_chirho.insert("llm_chirho".to_string(), 17);
    let book_chirho = PriceBookChirho {
        app_chirho: "priced-app-chirho".to_string(),
        owner_principal_chirho: "owner/price-chirho".to_string(),
        price_per_request_chirho: Some(5),
        effect_prices_chirho,
        external_markup_bps_chirho: 250,
        previous_chirho: Some(hash_chirho(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )),
        at_ms_chirho: 19,
    };
    assert_eq!(
        serde_json::to_value(book_chirho).unwrap(),
        serde_json::json!({
            "app_chirho": "priced-app-chirho",
            "owner_principal_chirho": "owner/price-chirho",
            "price_per_request_chirho": 5,
            "effect_prices_chirho": {
                "llm_chirho": 17
            },
            "external_markup_bps_chirho": 250,
            "previous_chirho": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "at_ms_chirho": 19
        })
    );
}

#[test]
fn asset_serialization_stays_stable_chirho() {
    assert_eq!(
        serde_json::to_string(&AssetChirho::CashChirho).unwrap(),
        "\"CashChirho\""
    );
    assert_eq!(
        serde_json::to_string(&AssetChirho::TokenChirho).unwrap(),
        "\"TokenChirho\""
    );
}

#[test]
fn billing_tags_omit_empty_optional_fields_chirho() {
    let empty_chirho = BillingTagsChirho::default();
    assert!(empty_chirho.is_empty_chirho());
    assert_eq!(
        serde_json::to_value(&empty_chirho).unwrap(),
        serde_json::json!({})
    );
    empty_chirho.validate_chirho().unwrap();

    let tags_chirho = BillingTagsChirho {
        user_id_chirho: Some("user/one-chirho".to_string()),
        app_id_chirho: None,
        run_id_chirho: Some(hash_chirho(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        )),
        effect_id_chirho: None,
    };
    assert!(!tags_chirho.is_empty_chirho());
    assert_eq!(
        serde_json::to_value(tags_chirho).unwrap(),
        serde_json::json!({
            "user_id_chirho": "user/one-chirho",
            "run_id_chirho": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        })
    );
}

#[test]
fn external_usage_record_serialization_stays_stable_chirho() {
    let record_chirho = ExternalUsageRecordChirho {
        seq_chirho: 11,
        schema_chirho: "external-usage-record-v1-chirho".to_string(),
        provider_chirho: "openrouter-chirho".to_string(),
        model_chirho: "deepseek-v4-chirho".to_string(),
        effect_chirho: "effect/external-chirho".to_string(),
        request_chirho: billing_wire_hash_chirho('a'),
        response_chirho: billing_wire_hash_chirho('b'),
        request_body_private_ref_chirho: Some(private_blob_ref_fixture_chirho('c')),
        response_body_private_ref_chirho: Some(private_blob_ref_fixture_chirho('d')),
        prompt_tokens_chirho: 13,
        completion_tokens_chirho: 17,
        total_tokens_chirho: 30,
        latency_ms_chirho: 41,
        price_record_seq_chirho: 3,
        input_microunits_per_token_chirho: 2,
        output_microunits_per_token_chirho: 5,
        cost_microunits_chirho: 111,
        cost_token_chirho: 1,
        ledger_seq_chirho: 9,
        suspense_ledger_seq_chirho: Some(10),
        billing_tags_chirho: billing_wire_tags_chirho(),
        at_ms_chirho: 99,
        sig_chirho: "sig-chirho".to_string(),
    };
    assert_eq!(
        serde_json::to_string(&record_chirho).unwrap(),
        r#"{"seq_chirho":11,"schema_chirho":"external-usage-record-v1-chirho","provider_chirho":"openrouter-chirho","model_chirho":"deepseek-v4-chirho","effect_chirho":"effect/external-chirho","request_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","response_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","request_body_private_ref_chirho":{"ciphertext_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","key_id_chirho":"key-c-chirho","nonce_chirho":"nonce-c-chirho","mac_chirho":"mac-c-chirho","alg_chirho":"xchacha20poly1305+blake3-keyed-mac/v1"},"response_body_private_ref_chirho":{"ciphertext_chirho":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","key_id_chirho":"key-d-chirho","nonce_chirho":"nonce-d-chirho","mac_chirho":"mac-d-chirho","alg_chirho":"xchacha20poly1305+blake3-keyed-mac/v1"},"prompt_tokens_chirho":13,"completion_tokens_chirho":17,"total_tokens_chirho":30,"latency_ms_chirho":41,"price_record_seq_chirho":3,"input_microunits_per_token_chirho":2,"output_microunits_per_token_chirho":5,"cost_microunits_chirho":111,"cost_token_chirho":1,"ledger_seq_chirho":9,"suspense_ledger_seq_chirho":10,"billing_tags_chirho":{"user_id_chirho":"caller-chirho","app_id_chirho":"app-chirho","run_id_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","effect_id_chirho":"effect-chirho"},"at_ms_chirho":99,"sig_chirho":"sig-chirho"}"#
    );
}

#[test]
fn external_usage_record_omits_empty_optional_fields_chirho() {
    let record_chirho = ExternalUsageRecordChirho {
        seq_chirho: 12,
        schema_chirho: String::new(),
        provider_chirho: "openrouter-chirho".to_string(),
        model_chirho: "deepseek-v4-chirho".to_string(),
        effect_chirho: "effect/external-empty-chirho".to_string(),
        request_chirho: billing_wire_hash_chirho('e'),
        response_chirho: billing_wire_hash_chirho('f'),
        request_body_private_ref_chirho: None,
        response_body_private_ref_chirho: None,
        prompt_tokens_chirho: 0,
        completion_tokens_chirho: 0,
        total_tokens_chirho: 0,
        latency_ms_chirho: 1,
        price_record_seq_chirho: 0,
        input_microunits_per_token_chirho: 0,
        output_microunits_per_token_chirho: 0,
        cost_microunits_chirho: 0,
        cost_token_chirho: 0,
        ledger_seq_chirho: 0,
        suspense_ledger_seq_chirho: None,
        billing_tags_chirho: BillingTagsChirho::default(),
        at_ms_chirho: 100,
        sig_chirho: "sig-empty-chirho".to_string(),
    };
    assert_eq!(
        serde_json::to_string(&record_chirho).unwrap(),
        r#"{"seq_chirho":12,"provider_chirho":"openrouter-chirho","model_chirho":"deepseek-v4-chirho","effect_chirho":"effect/external-empty-chirho","request_chirho":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","response_chirho":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","prompt_tokens_chirho":0,"completion_tokens_chirho":0,"total_tokens_chirho":0,"latency_ms_chirho":1,"price_record_seq_chirho":0,"input_microunits_per_token_chirho":0,"output_microunits_per_token_chirho":0,"cost_microunits_chirho":0,"cost_token_chirho":0,"ledger_seq_chirho":0,"billing_tags_chirho":{},"at_ms_chirho":100,"sig_chirho":"sig-empty-chirho"}"#
    );
}

#[test]
fn billing_policy_and_compensation_message_bytes_are_hard_wire_chirho() {
    let policy_chirho = BillingPolicyRecordChirho {
        seq_chirho: 1,
        schema_chirho: BILLING_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
        app_chirho: "app-chirho".to_string(),
        owner_principal_chirho: "owner/app-chirho".to_string(),
        billing_policy_chirho: billing_wire_hash_chirho('a'),
        previous_chirho: Some(billing_wire_hash_chirho('b')),
        at_ms_chirho: 10,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: "sig-chirho".to_string(),
    };
    assert_billing_message_bytes_chirho(
        "billing policy message bytes",
        billing_contract_chirho::policy_record_message_chirho(&policy_chirho).unwrap(),
        br#"{"seq_chirho":1,"schema_chirho":"billing-policy-record-v1-chirho","app_chirho":"app-chirho","owner_principal_chirho":"owner/app-chirho","billing_policy_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","previous_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","at_ms_chirho":10}"#,
    );
    assert_eq!(
        serde_json::to_string(&policy_chirho).unwrap(),
        r#"{"seq_chirho":1,"schema_chirho":"billing-policy-record-v1-chirho","app_chirho":"app-chirho","owner_principal_chirho":"owner/app-chirho","billing_policy_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","previous_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","at_ms_chirho":10,"sig_chirho":"sig-chirho"}"#,
        "billing policy v1 stored bytes"
    );

    let compensation_chirho = BillingCompensationRecordChirho {
        seq_chirho: 2,
        schema_chirho: BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO.to_string(),
        original_usage_seq_chirho: 3,
        ledger_seq_chirho: 4,
        app_chirho: "app-chirho".to_string(),
        caller_chirho: "caller-chirho".to_string(),
        payer_chirho: "payer-chirho".to_string(),
        amount_token_chirho: 17,
        reason_chirho: "refund-chirho".to_string(),
        billing_tags_chirho: billing_wire_tags_chirho(),
        at_ms_chirho: 11,
        sig_chirho: "sig-chirho".to_string(),
    };
    assert_billing_message_bytes_chirho(
        "billing compensation message bytes",
        billing_contract_chirho::compensation_record_message_chirho(&compensation_chirho).unwrap(),
        br#"{"seq_chirho":2,"schema_chirho":"billing-compensation-record-v1-chirho","original_usage_seq_chirho":3,"ledger_seq_chirho":4,"app_chirho":"app-chirho","caller_chirho":"caller-chirho","payer_chirho":"payer-chirho","amount_token_chirho":17,"reason_chirho":"refund-chirho","billing_tags_chirho":{"user_id_chirho":"caller-chirho","app_id_chirho":"app-chirho","run_id_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","effect_id_chirho":"effect-chirho"},"at_ms_chirho":11}"#,
    );
}

#[test]
fn billing_usage_message_bytes_are_hard_wire_chirho() {
    let mut legacy_chirho = billing_wire_usage_record_chirho();
    legacy_chirho.schema_chirho.clear();
    legacy_chirho.billing_policy_chirho = None;
    legacy_chirho.billing_tags_chirho = BillingTagsChirho::default();
    assert_billing_message_bytes_chirho(
        "legacy billing usage message bytes",
        billing_contract_chirho::usage_record_message_chirho(&legacy_chirho).unwrap(),
        br#"{"seq_chirho":3,"app_chirho":"app-chirho","effect_chirho":"effect-chirho","caller_chirho":"caller-chirho","payer_chirho":"payer-chirho","payer_kind_chirho":"UserChirho","provider_chirho":"provider-chirho","price_chirho":17,"price_book_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","billing_policy_chirho":null,"mode_chirho":"UserPaysChirho","ledger_seq_chirho":4,"at_ms_chirho":99}"#,
    );

    let tagged_chirho = billing_wire_usage_record_chirho();
    assert_billing_message_bytes_chirho(
        "tagged billing usage message bytes",
        billing_contract_chirho::usage_record_message_chirho(&tagged_chirho).unwrap(),
        br#"{"seq_chirho":3,"schema_chirho":"billing-usage-record-v1-chirho","app_chirho":"app-chirho","effect_chirho":"effect-chirho","caller_chirho":"caller-chirho","payer_chirho":"payer-chirho","payer_kind_chirho":"UserChirho","provider_chirho":"provider-chirho","price_chirho":17,"price_book_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","billing_policy_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","mode_chirho":"UserPaysChirho","ledger_seq_chirho":4,"billing_tags_chirho":{"user_id_chirho":"caller-chirho","app_id_chirho":"app-chirho","run_id_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","effect_id_chirho":"effect-chirho"},"at_ms_chirho":99}"#,
    );

    let mut tagged_empty_schema_chirho = tagged_chirho.clone();
    tagged_empty_schema_chirho.schema_chirho.clear();
    assert_billing_message_bytes_chirho(
        "tagged empty-schema billing usage message bytes",
        billing_contract_chirho::usage_record_message_chirho(&tagged_empty_schema_chirho).unwrap(),
        br#"{"seq_chirho":3,"app_chirho":"app-chirho","effect_chirho":"effect-chirho","caller_chirho":"caller-chirho","payer_chirho":"payer-chirho","payer_kind_chirho":"UserChirho","provider_chirho":"provider-chirho","price_chirho":17,"price_book_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","billing_policy_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","mode_chirho":"UserPaysChirho","ledger_seq_chirho":4,"billing_tags_chirho":{"user_id_chirho":"caller-chirho","app_id_chirho":"app-chirho","run_id_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","effect_id_chirho":"effect-chirho"},"at_ms_chirho":99}"#,
    );

    let mut cache_chirho = billing_wire_usage_record_chirho();
    cache_chirho.cache_hit_chirho = true;
    cache_chirho.billing_policy_chirho = None;
    cache_chirho.billing_tags_chirho = BillingTagsChirho::default();
    assert_billing_message_bytes_chirho(
        "cache-hit billing usage message bytes",
        billing_contract_chirho::usage_record_message_chirho(&cache_chirho).unwrap(),
        br#"{"seq_chirho":3,"schema_chirho":"billing-usage-record-v1-chirho","app_chirho":"app-chirho","effect_chirho":"effect-chirho","caller_chirho":"caller-chirho","payer_chirho":"payer-chirho","payer_kind_chirho":"UserChirho","provider_chirho":"provider-chirho","price_chirho":17,"price_book_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","billing_policy_chirho":null,"mode_chirho":"UserPaysChirho","ledger_seq_chirho":4,"cache_hit_chirho":true,"billing_tags_chirho":{},"at_ms_chirho":99}"#,
    );

    let mut split_cache_chirho = cache_chirho.clone();
    split_cache_chirho.platform_fee_chirho = 5;
    split_cache_chirho.owner_margin_chirho = 12;
    assert_billing_message_bytes_chirho(
        "split cache-hit billing usage message bytes",
        billing_contract_chirho::usage_record_message_chirho(&split_cache_chirho).unwrap(),
        br#"{"seq_chirho":3,"schema_chirho":"billing-usage-record-v1-chirho","app_chirho":"app-chirho","effect_chirho":"effect-chirho","caller_chirho":"caller-chirho","payer_chirho":"payer-chirho","payer_kind_chirho":"UserChirho","provider_chirho":"provider-chirho","price_chirho":17,"price_book_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","billing_policy_chirho":null,"mode_chirho":"UserPaysChirho","ledger_seq_chirho":4,"cache_hit_chirho":true,"external_provider_chirho":null,"external_cost_token_chirho":0,"platform_fee_chirho":5,"owner_margin_chirho":12,"billing_tags_chirho":{},"at_ms_chirho":99}"#,
    );

    let mut nway_chirho = billing_wire_usage_record_chirho();
    nway_chirho.nway_settlement_chirho = true;
    nway_chirho.external_provider_chirho = Some("openrouter-chirho".to_string());
    nway_chirho.external_cost_token_chirho = 9;
    nway_chirho.platform_fee_chirho = 2;
    nway_chirho.owner_margin_chirho = 6;
    assert_billing_message_bytes_chirho(
        "N-way billing usage message bytes",
        billing_contract_chirho::usage_record_message_chirho(&nway_chirho).unwrap(),
        br#"{"seq_chirho":3,"schema_chirho":"billing-usage-record-v1-chirho","app_chirho":"app-chirho","effect_chirho":"effect-chirho","caller_chirho":"caller-chirho","payer_chirho":"payer-chirho","payer_kind_chirho":"UserChirho","provider_chirho":"provider-chirho","price_chirho":17,"price_book_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","billing_policy_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","mode_chirho":"UserPaysChirho","ledger_seq_chirho":4,"nway_settlement_chirho":true,"external_provider_chirho":"openrouter-chirho","external_cost_token_chirho":9,"platform_fee_chirho":2,"owner_margin_chirho":6,"billing_tags_chirho":{"user_id_chirho":"caller-chirho","app_id_chirho":"app-chirho","run_id_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","effect_id_chirho":"effect-chirho"},"at_ms_chirho":99}"#,
    );

    let mut held_nway_chirho = nway_chirho;
    held_nway_chirho.credit_hold_chirho = Some(BillingCreditHoldChirho {
        hold_id_chirho: "hold-chirho".to_string(),
        hold_account_chirho: "hold/account-chirho".to_string(),
        authorized_token_chirho: 22,
        released_token_chirho: 5,
        reserve_ledger_seq_chirho: 7,
    });
    assert_billing_message_bytes_chirho(
        "held N-way billing usage message bytes",
        billing_contract_chirho::usage_record_message_chirho(&held_nway_chirho).unwrap(),
        br#"{"seq_chirho":3,"schema_chirho":"billing-usage-record-v1-chirho","app_chirho":"app-chirho","effect_chirho":"effect-chirho","caller_chirho":"caller-chirho","payer_chirho":"payer-chirho","payer_kind_chirho":"UserChirho","provider_chirho":"provider-chirho","price_chirho":17,"price_book_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","billing_policy_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","mode_chirho":"UserPaysChirho","ledger_seq_chirho":4,"nway_settlement_chirho":true,"external_provider_chirho":"openrouter-chirho","external_cost_token_chirho":9,"platform_fee_chirho":2,"owner_margin_chirho":6,"credit_hold_chirho":{"hold_id_chirho":"hold-chirho","hold_account_chirho":"hold/account-chirho","authorized_token_chirho":22,"released_token_chirho":5,"reserve_ledger_seq_chirho":7},"billing_tags_chirho":{"user_id_chirho":"caller-chirho","app_id_chirho":"app-chirho","run_id_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","effect_id_chirho":"effect-chirho"},"at_ms_chirho":99}"#,
    );
}

#[test]
fn ledger_entry_omits_legacy_empty_schema_chirho() {
    let entry_chirho = LedgerEntryChirho {
        seq_chirho: 3,
        schema_chirho: String::new(),
        memo_chirho: "move tokens".to_string(),
        postings_chirho: vec![
            PostingChirho {
                account_chirho: "alice".to_string(),
                asset_chirho: AssetChirho::TokenChirho,
                amount_chirho: -10,
            },
            PostingChirho {
                account_chirho: "bob".to_string(),
                asset_chirho: AssetChirho::TokenChirho,
                amount_chirho: 10,
            },
        ],
        billing_tags_chirho: BillingTagsChirho::default(),
        at_ms_chirho: 23,
        sig_chirho: "sig-chirho".to_string(),
        op_binding_chirho: None,
    };
    let value_chirho = serde_json::to_value(entry_chirho).unwrap();
    assert!(value_chirho.get("schema_chirho").is_none());
    assert_eq!(
        value_chirho.get("billing_tags_chirho"),
        Some(&serde_json::json!({}))
    );
}

#[test]
fn accounting_enums_serialization_stays_stable_chirho() {
    assert_eq!(
        serde_json::to_string(&AccountingAccountKindChirho::AssetChirho).unwrap(),
        "\"AssetChirho\""
    );
    assert_eq!(
        serde_json::to_string(&AccountingAccountKindChirho::RevenueChirho).unwrap(),
        "\"RevenueChirho\""
    );
    assert_eq!(
        serde_json::to_string(&AccountingAdapterChirho::QuickBooksChirho).unwrap(),
        "\"QuickBooksChirho\""
    );
    assert_eq!(
        serde_json::to_string(&AccountingAdapterChirho::NetSuiteChirho).unwrap(),
        "\"NetSuiteChirho\""
    );
}

#[test]
fn accounting_export_and_views_omit_legacy_empty_schema_chirho() {
    let empty_profit_and_loss_chirho = AccountingProfitAndLossChirho {
        rows_chirho: Vec::new(),
        revenue_total_by_asset_chirho: BTreeMap::new(),
        expense_total_by_asset_chirho: BTreeMap::new(),
        net_income_by_asset_chirho: BTreeMap::new(),
    };
    let empty_balance_sheet_chirho = AccountingBalanceSheetChirho {
        rows_chirho: Vec::new(),
        asset_total_by_asset_chirho: BTreeMap::new(),
        liability_total_by_asset_chirho: BTreeMap::new(),
        equity_total_by_asset_chirho: BTreeMap::new(),
        current_earnings_by_asset_chirho: BTreeMap::new(),
        accounting_equation_delta_by_asset_chirho: BTreeMap::new(),
    };
    let empty_tax_summary_chirho = AccountingTaxSummaryChirho {
        rows_chirho: Vec::new(),
        taxable_revenue_by_asset_chirho: BTreeMap::new(),
        deductible_expense_by_asset_chirho: BTreeMap::new(),
        scope_note_chirho: "scope-chirho".to_string(),
    };
    let period_close_chirho = AccountingPeriodCloseChirho {
        ledger_cutoff_chirho: 0,
        period_entry_count_chirho: 0,
        period_line_count_chirho: 0,
        balanced_by_asset_chirho: BTreeMap::new(),
    };
    let export_chirho = AccountingExportChirho {
        schema_chirho: String::new(),
        generated_ms_chirho: 1,
        period_start_ms_chirho: 2,
        period_end_ms_chirho: 3,
        ledger_verified_count_chirho: 4,
        ledger_source_digest_chirho: "digest-chirho".to_string(),
        chart_of_accounts_chirho: Vec::new(),
        journal_rows_chirho: Vec::new(),
        trial_balance_chirho: Vec::new(),
        profit_and_loss_chirho: empty_profit_and_loss_chirho.clone(),
        balance_sheet_chirho: empty_balance_sheet_chirho.clone(),
        tax_summary_chirho: empty_tax_summary_chirho.clone(),
        period_close_chirho: period_close_chirho.clone(),
        scope_notes_chirho: Vec::new(),
    };
    let views_chirho = AccountingFinancialViewsChirho {
        schema_chirho: String::new(),
        generated_ms_chirho: 1,
        period_start_ms_chirho: 2,
        period_end_ms_chirho: 3,
        ledger_verified_count_chirho: 4,
        ledger_source_digest_chirho: "digest-chirho".to_string(),
        profit_and_loss_chirho: empty_profit_and_loss_chirho,
        balance_sheet_chirho: empty_balance_sheet_chirho,
        tax_summary_chirho: empty_tax_summary_chirho,
        trial_balance_chirho: Vec::new(),
        period_close_chirho,
        scope_notes_chirho: Vec::new(),
    };
    assert!(serde_json::to_value(export_chirho)
        .unwrap()
        .get("schema_chirho")
        .is_none());
    assert!(serde_json::to_value(views_chirho)
        .unwrap()
        .get("schema_chirho")
        .is_none());
}

#[test]
fn resource_signed_records_omit_legacy_empty_schema_chirho() {
    let policy_record_chirho = ResourcePolicyRecordChirho {
        seq_chirho: 1,
        schema_chirho: String::new(),
        app_chirho: "resource-app-chirho".to_string(),
        owner_principal_chirho: "owner/resource-chirho".to_string(),
        resource_policy_chirho: hash_chirho(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ),
        previous_chirho: None,
        at_ms_chirho: 2,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: "sig-policy-chirho".to_string(),
    };
    let unset_record_chirho = ResourcePolicyUnsetRecordChirho {
        seq_chirho: 3,
        schema_chirho: String::new(),
        app_chirho: "resource-app-chirho".to_string(),
        owner_principal_chirho: "owner/resource-chirho".to_string(),
        previous_chirho: hash_chirho(
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        ),
        at_ms_chirho: 4,
        sig_chirho: "sig-unset-chirho".to_string(),
    };
    assert!(serde_json::to_value(policy_record_chirho)
        .unwrap()
        .get("schema_chirho")
        .is_none());
    assert!(serde_json::to_value(unset_record_chirho)
        .unwrap()
        .get("schema_chirho")
        .is_none());
}

#[test]
fn resource_usage_record_omits_empty_schema_and_optional_surfaces_chirho() {
    let usage_record_chirho = ResourceUsageRecordChirho {
        seq_chirho: 5,
        schema_chirho: String::new(),
        app_chirho: "resource-app-chirho".to_string(),
        user_chirho: "user/resource-chirho".to_string(),
        actor_chirho: "user/resource-chirho".to_string(),
        section_chirho: "request_chirho".to_string(),
        action_chirho: "default_chirho".to_string(),
        effect_chirho: None,
        run_chirho: None,
        resource_policy_chirho: hash_chirho(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        charges_chirho: vec![ResourceChargeChirho {
            resource_chirho: "credit_chirho".to_string(),
            amount_chirho: 1,
        }],
        bridges_chirho: Vec::new(),
        decision_chirho: ResourceDecisionChirho::AllowedChirho,
        at_ms_chirho: 6,
        sig_chirho: "sig-usage-chirho".to_string(),
    };
    let value_chirho = serde_json::to_value(usage_record_chirho).unwrap();
    assert!(value_chirho.get("schema_chirho").is_none());
    assert!(value_chirho.get("effect_chirho").is_none());
    assert!(value_chirho.get("run_chirho").is_none());
    assert!(value_chirho.get("bridges_chirho").is_none());
}

#[test]
fn resource_enums_and_legacy_route_default_stay_stable_chirho() {
    assert_eq!(
        serde_json::to_string(&ResourceBridgeKindChirho::BillingUsageChirho).unwrap(),
        "\"BillingUsageChirho\""
    );
    assert_eq!(
        serde_json::to_string(&ResourceDecisionChirho::AllowedChirho).unwrap(),
        "\"AllowedChirho\""
    );
    assert_eq!(
        serde_json::to_string(&ResourceOverageChirho::FailClosedChirho).unwrap(),
        "\"FailClosedChirho\""
    );

    let default_closed_chirho: ResourcePolicyInputChirho = serde_json::from_str(
        r#"{"meters_chirho":[{"resource_chirho":"public_write_chirho","unit_chirho":"write","app_limit_chirho":1,"overage_chirho":"FailClosedChirho"}],"actions_chirho":[{"section_chirho":"request_chirho","action_chirho":"default_chirho","charges_chirho":[{"resource_chirho":"public_write_chirho","amount_chirho":1}]}]}"#,
    )
    .unwrap();
    assert!(!default_closed_chirho.actions_chirho[0].allow_anonymous_chirho);

    let input_chirho: ResourcePolicyInputChirho = serde_json::from_str(
        r#"{
                "meters_chirho": [{
                    "resource_chirho": "public_write_chirho",
                    "unit_chirho": "write",
                    "app_limit_chirho": 1,
                    "overage_chirho": {
                        "RouteChirho": {
                            "route_chirho": "overage"
                        }
                    }
                }],
                "actions_chirho": [{
                    "section_chirho": "request_chirho",
                    "action_chirho": "default_chirho",
                    "allow_anonymous_chirho": true,
                    "charges_chirho": [{
                        "resource_chirho": "public_write_chirho",
                        "amount_chirho": 1
                    }]
                }]
            }"#,
    )
    .unwrap();
    assert!(matches!(
        input_chirho.meters_chirho[0].overage_chirho,
        ResourceOverageChirho::RouteChirho {
            ref route_chirho,
            forward_request_body_chirho: false,
        } if route_chirho == "overage"
    ));
}

#[test]
fn billing_signed_records_omit_legacy_empty_schema_chirho() {
    let policy_record_chirho = BillingPolicyRecordChirho {
        seq_chirho: 1,
        schema_chirho: String::new(),
        app_chirho: "billing-app-chirho".to_string(),
        owner_principal_chirho: "owner/billing-chirho".to_string(),
        billing_policy_chirho: hash_chirho(
            "1111111111111111111111111111111111111111111111111111111111111111",
        ),
        previous_chirho: None,
        at_ms_chirho: 2,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: "sig-policy-chirho".to_string(),
    };
    let compensation_record_chirho = BillingCompensationRecordChirho {
        seq_chirho: 3,
        schema_chirho: String::new(),
        original_usage_seq_chirho: 4,
        ledger_seq_chirho: 5,
        app_chirho: "billing-app-chirho".to_string(),
        caller_chirho: "user/billing-chirho".to_string(),
        payer_chirho: "user/billing-chirho".to_string(),
        amount_token_chirho: 17,
        reason_chirho: "refund-chirho".to_string(),
        billing_tags_chirho: BillingTagsChirho::default(),
        at_ms_chirho: 6,
        sig_chirho: "sig-compensation-chirho".to_string(),
    };
    assert_eq!(
        serde_json::to_string(&policy_record_chirho).unwrap(),
        r#"{"seq_chirho":1,"app_chirho":"billing-app-chirho","owner_principal_chirho":"owner/billing-chirho","billing_policy_chirho":"1111111111111111111111111111111111111111111111111111111111111111","previous_chirho":null,"at_ms_chirho":2,"sig_chirho":"sig-policy-chirho"}"#,
        "blank-schema billing policy stored bytes"
    );
    assert!(serde_json::to_value(policy_record_chirho)
        .unwrap()
        .get("schema_chirho")
        .is_none());
    assert!(serde_json::to_value(compensation_record_chirho)
        .unwrap()
        .get("schema_chirho")
        .is_none());
}

#[test]
fn billing_usage_record_omits_optional_surfaces_chirho() {
    let record_chirho = BillingUsageRecordChirho {
        seq_chirho: 7,
        schema_chirho: String::new(),
        app_chirho: "billing-app-chirho".to_string(),
        effect_chirho: "llm_chirho".to_string(),
        caller_chirho: "user/billing-chirho".to_string(),
        payer_chirho: "owner/billing-chirho".to_string(),
        payer_kind_chirho: BillingPayerKindChirho::AppOwnerChirho,
        provider_chirho: "provider/chirho".to_string(),
        price_chirho: 29,
        price_book_chirho: hash_chirho(
            "2222222222222222222222222222222222222222222222222222222222222222",
        ),
        billing_policy_chirho: None,
        mode_chirho: BillingPolicyModeChirho::AppPaysChirho,
        ledger_seq_chirho: 8,
        cache_hit_chirho: false,
        nway_settlement_chirho: false,
        external_provider_chirho: None,
        external_cost_token_chirho: 0,
        platform_fee_chirho: 0,
        owner_margin_chirho: 0,
        credit_hold_chirho: None,
        billing_tags_chirho: BillingTagsChirho::default(),
        at_ms_chirho: 9,
        sig_chirho: "sig-usage-chirho".to_string(),
    };
    let value_chirho = serde_json::to_value(record_chirho).unwrap();
    assert!(value_chirho.get("schema_chirho").is_none());
    assert!(value_chirho.get("external_provider_chirho").is_none());
    assert!(value_chirho.get("credit_hold_chirho").is_none());
    assert_eq!(
        value_chirho.get("billing_tags_chirho"),
        Some(&serde_json::json!({}))
    );
    assert_eq!(
        value_chirho.get("cache_hit_chirho"),
        Some(&serde_json::json!(false))
    );
    assert_eq!(
        value_chirho.get("nway_settlement_chirho"),
        Some(&serde_json::json!(false))
    );
}

#[test]
fn billing_enums_labels_and_parse_stay_stable_chirho() {
    assert_eq!(
        serde_json::to_string(&BillingOverageChirho::FailClosedChirho).unwrap(),
        "\"FailClosedChirho\""
    );
    assert_eq!(
        serde_json::to_string(&BillingPayerKindChirho::SubsidyOwnerChirho).unwrap(),
        "\"SubsidyOwnerChirho\""
    );
    assert_eq!(
        BillingOverageChirho::parse_chirho("fall-through-user-pays").unwrap(),
        BillingOverageChirho::FallThroughUserPaysChirho
    );
    assert_eq!(
        BillingPolicyModeChirho::SubsidyChirho {
            per_user_budget_chirho: 31,
            overage_chirho: BillingOverageChirho::FailClosedChirho,
        }
        .label_chirho(),
        "subsidy:31:fail-closed"
    );
    assert_eq!(
        BillingRollupAxisChirho::parse_chirho("effect").unwrap(),
        BillingRollupAxisChirho::EffectChirho
    );
    assert!(BillingRollupAxisChirho::parse_chirho("provider").is_err());
}

#[test]
fn credit_hold_record_roundtrips_existing_jsonl_bytes_chirho() {
    assert_byte_exact_json_roundtrip_chirho::<CreditHoldRecordChirho>(
        "{\"seq_chirho\":2,\"schema_chirho\":\"credit-hold-record-v1-chirho\",\"hold_id_chirho\":\"hold-1-chirho\",\"hold_account_chirho\":\"platform/credit-hold/hold-1-chirho\",\"app_chirho\":\"app-chirho\",\"effect_chirho\":\"effect-chirho\",\"caller_chirho\":\"caller-chirho\",\"payer_chirho\":\"payer-chirho\",\"authorized_token_chirho\":100,\"settled_token_chirho\":80,\"released_token_chirho\":20,\"reserve_ledger_seq_chirho\":7,\"settlement_ledger_seq_chirho\":8,\"release_ledger_seq_chirho\":9,\"status_chirho\":\"ReleasedChirho\",\"billing_tags_chirho\":{\"user_id_chirho\":\"user/one-chirho\"},\"at_ms_chirho\":10,\"sig_chirho\":\"sig-hold-chirho\"}",
    );
    assert_byte_exact_json_roundtrip_chirho::<CreditHoldRecordChirho>(
        "{\"seq_chirho\":0,\"schema_chirho\":\"credit-hold-record-v1-chirho\",\"hold_id_chirho\":\"hold-open-chirho\",\"hold_account_chirho\":\"platform/credit-hold/hold-open-chirho\",\"app_chirho\":\"app-chirho\",\"effect_chirho\":\"effect-chirho\",\"caller_chirho\":\"caller-chirho\",\"payer_chirho\":\"payer-chirho\",\"authorized_token_chirho\":100,\"settled_token_chirho\":0,\"released_token_chirho\":0,\"reserve_ledger_seq_chirho\":7,\"status_chirho\":\"OpenChirho\",\"billing_tags_chirho\":{},\"at_ms_chirho\":8,\"sig_chirho\":\"sig-open-hold-chirho\"}",
    );
    assert_byte_exact_json_roundtrip_chirho::<CreditHoldRecordChirho>(
        "{\"seq_chirho\":1,\"schema_chirho\":\"credit-hold-record-v1-chirho\",\"hold_id_chirho\":\"hold-settled-chirho\",\"hold_account_chirho\":\"platform/credit-hold/hold-settled-chirho\",\"app_chirho\":\"app-chirho\",\"effect_chirho\":\"effect-chirho\",\"caller_chirho\":\"caller-chirho\",\"payer_chirho\":\"payer-chirho\",\"authorized_token_chirho\":100,\"settled_token_chirho\":100,\"released_token_chirho\":0,\"reserve_ledger_seq_chirho\":7,\"settlement_ledger_seq_chirho\":8,\"status_chirho\":\"SettledChirho\",\"billing_tags_chirho\":{},\"at_ms_chirho\":9,\"sig_chirho\":\"sig-settled-hold-chirho\"}",
    );
    assert_byte_exact_json_roundtrip_chirho::<CreditHoldRecordChirho>(
        "{\"seq_chirho\":5,\"hold_id_chirho\":\"hold-legacy-chirho\",\"hold_account_chirho\":\"platform/credit-hold/hold-legacy-chirho\",\"app_chirho\":\"app-chirho\",\"effect_chirho\":\"effect-chirho\",\"caller_chirho\":\"caller-chirho\",\"payer_chirho\":\"payer-chirho\",\"authorized_token_chirho\":50,\"settled_token_chirho\":0,\"released_token_chirho\":50,\"reserve_ledger_seq_chirho\":6,\"release_ledger_seq_chirho\":7,\"status_chirho\":\"ReleasedChirho\",\"billing_tags_chirho\":{},\"at_ms_chirho\":14,\"sig_chirho\":\"sig-legacy-hold-chirho\"}",
    );
}
