// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Saga wire proofs: canonical roundtrip, the malleability RED family, sign-then-attach content,
//! DERIVED saga ids, and the cross-domain refusal (saga ≠ journal ≠ registry — #4901 b-i).

use crate::record_chirho::{
    canonical_saga_line_chirho, derive_saga_id_chirho, parse_canonical_saga_line_chirho,
    saga_root_signed_content_chirho, SagaOpChirho, SagaRecordChirho, SagaStepPlanChirho,
    SAGA_RECORD_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindRefChirho, ClusterIdChirho, DigestChirho};

fn sample_step_chirho() -> SagaStepPlanChirho {
    SagaStepPlanChirho {
        cluster_chirho: ClusterIdChirho("cluster-a-chirho".into()),
        owner_chirho: "alice-chirho".into(),
        kind_chirho: "money-chirho".into(),
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("policy-money-v1-chirho".into())),
        amount_chirho: 10,
        settlement_owner_chirho: "platform-a-chirho".into(),
    }
}

fn sample_record_chirho() -> SagaRecordChirho {
    SagaRecordChirho {
        schema_chirho: SAGA_RECORD_SCHEMA_V1_CHIRHO.into(),
        seq_chirho: 0,
        prev_chirho: "anchor-fixture-chirho".into(),
        saga_log_id_chirho: "saga-log-alpha-chirho".into(),
        saga_id_chirho: derive_saga_id_chirho("saga-log-alpha-chirho", "token-1-chirho"),
        op_chirho: SagaOpChirho::IntentChirho {
            token_chirho: "token-1-chirho".into(),
            steps_chirho: vec![sample_step_chirho()],
            opened_at_ms_chirho: 1_000,
            ttl_ms_chirho: 60_000,
        },
        root_sig_chirho: "root-sig-fixture-chirho".into(),
    }
}

#[test]
fn canonical_line_roundtrips_byte_exact_chirho() {
    let record_chirho = sample_record_chirho();
    let line_chirho = canonical_saga_line_chirho(&record_chirho).unwrap();
    let parsed_chirho = parse_canonical_saga_line_chirho(&line_chirho).unwrap();
    assert_eq!(parsed_chirho, record_chirho);
    assert_eq!(
        canonical_saga_line_chirho(&parsed_chirho).unwrap(),
        line_chirho
    );
}

#[test]
fn malleability_family_refuses_chirho() {
    let line_chirho = canonical_saga_line_chirho(&sample_record_chirho()).unwrap();
    for mutated_chirho in [
        format!(" {line_chirho}"),
        format!("{line_chirho}\n"),
        format!("{line_chirho}x"),
        line_chirho.replacen(
            "\"schema_chirho\"",
            "\"injected_chirho\":true,\"schema_chirho\"",
            1,
        ),
        line_chirho.replacen(
            SAGA_RECORD_SCHEMA_V1_CHIRHO,
            "ledger-saga-record-v9-chirho",
            1,
        ),
    ] {
        assert!(
            parse_canonical_saga_line_chirho(&mutated_chirho).is_err(),
            "mutated saga line must refuse: {mutated_chirho:.60}"
        );
    }
}

#[test]
fn cross_domain_lines_refuse_chirho() {
    // A ledger JOURNAL record line (its own schema tag) must refuse the saga parser on the schema
    // probe alone — the b-i router law. (A registry line refuses identically; one representative.)
    let journal_shaped_chirho = format!(
        "{{\"schema_chirho\":\"{}\",\"seq_chirho\":1}}",
        cairn_ledger_model_chirho::wire_chirho::LEDGER_RECORD_SCHEMA_V1_CHIRHO
    );
    let refusal_chirho = parse_canonical_saga_line_chirho(&journal_shaped_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        refusal_chirho.contains("unsupported saga record schema"),
        "cross-domain refusal must fire on the schema tag: {refusal_chirho}"
    );
}

#[test]
fn saga_id_is_derived_and_domain_separated_chirho() {
    let id_a_chirho = derive_saga_id_chirho("saga-log-alpha-chirho", "token-1-chirho");
    let id_a_again_chirho = derive_saga_id_chirho("saga-log-alpha-chirho", "token-1-chirho");
    assert_eq!(
        id_a_chirho, id_a_again_chirho,
        "crash-resume re-derives the SAME id"
    );
    assert_ne!(
        id_a_chirho,
        derive_saga_id_chirho("saga-log-alpha-chirho", "token-2-chirho"),
        "tokens separate sagas"
    );
    assert_ne!(
        id_a_chirho,
        derive_saga_id_chirho("saga-log-beta-chirho", "token-1-chirho"),
        "logs separate saga-id spaces"
    );
    assert_eq!(id_a_chirho.0.len(), 64);
}

#[test]
fn sign_then_attach_content_blanks_only_the_sig_chirho() {
    let record_chirho = sample_record_chirho();
    let content_chirho = saga_root_signed_content_chirho(&record_chirho).unwrap();
    assert!(content_chirho.contains("\"root_sig_chirho\":\"\""));
    assert!(content_chirho.contains("token-1-chirho"));
    assert_ne!(
        content_chirho,
        canonical_saga_line_chirho(&record_chirho).unwrap()
    );
}

#[test]
fn empty_plan_refuses_at_the_wire_chirho() {
    let mut record_chirho = sample_record_chirho();
    record_chirho.op_chirho = SagaOpChirho::IntentChirho {
        token_chirho: "token-1-chirho".into(),
        steps_chirho: Vec::new(),
        opened_at_ms_chirho: 1_000,
        ttl_ms_chirho: 60_000,
    };
    assert!(canonical_saga_line_chirho(&record_chirho).is_err());
}
