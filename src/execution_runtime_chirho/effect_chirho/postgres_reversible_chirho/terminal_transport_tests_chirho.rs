// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

fn terminal_response_chirho() -> PostgresEffectResponseChirho {
    PostgresEffectResponseChirho {
        schema_chirho: POSTGRES_EFFECT_RESPONSE_SCHEMA_CHIRHO.to_owned(),
        intent_ref_chirho: DigestChirho("11".repeat(32)),
        hold_seq_chirho: 7,
        hold_record_digest_chirho: DigestChirho("22".repeat(32)),
        hold_hlc_chirho: HlcChirho {
            physical_ms_chirho: 1_000,
            logical_chirho: 1,
        },
        terminal_seq_chirho: 8,
        terminal_record_digest_chirho: DigestChirho("33".repeat(32)),
        terminal_hlc_chirho: HlcChirho {
            physical_ms_chirho: 1_001,
            logical_chirho: 0,
        },
        outcome_ref_chirho: DigestChirho("44".repeat(32)),
        disposition_chirho: EffectTerminalDispositionChirho::CommittedChirho {
            result_ref_chirho: DigestChirho("55".repeat(32)),
        },
    }
}

#[test]
fn terminal_transport_classification_requires_exact_canonical_bytes_chirho() {
    let response_chirho = terminal_response_chirho();
    let canonical_chirho = serde_json::to_vec(&response_chirho).unwrap();
    assert_eq!(
        parse_canonical_postgres_effect_terminal_disposition_chirho(&canonical_chirho).unwrap(),
        response_chirho.disposition_chirho
    );

    let pretty_chirho = serde_json::to_vec_pretty(&response_chirho).unwrap();
    assert!(parse_canonical_postgres_effect_terminal_disposition_chirho(&pretty_chirho).is_err());

    let mut unknown_field_chirho = serde_json::to_value(&response_chirho).unwrap();
    unknown_field_chirho
        .as_object_mut()
        .unwrap()
        .insert("caller_amount_chirho".to_owned(), serde_json::json!(10));
    assert!(parse_canonical_postgres_effect_terminal_disposition_chirho(
        &serde_json::to_vec(&unknown_field_chirho).unwrap()
    )
    .is_err());
}
