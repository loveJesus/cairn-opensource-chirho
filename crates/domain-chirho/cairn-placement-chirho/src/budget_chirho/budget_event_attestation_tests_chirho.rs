// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the budget-event envelope.
//!
//! The centrepiece is [`a_self_reported_digest_is_not_trusted_chirho`]. Every other refusal here is
//! hygiene; that one is the attack. A record carries its own `intent_digest_chirho` AND a signature
//! over it, so a verifier that believed the declared digest would be checking a signature over a
//! number the record chose — and the intent underneath could say anything, including a reservation of
//! whatever size the author liked.

use super::*;

const KEY_CHIRHO: &str = "budget-authority-key-chirho";
const BUDGET_CHIRHO: &str = "budget-a-chirho";
const ROOT_KEY_CHIRHO: &str = "root-key-a-chirho";
const TENANT_CHIRHO: &str = "tenant-a-chirho";
const FUNDING_DIGEST_CHIRHO: &str = "funding-digest-a-chirho";

struct AuthorityChirho;

impl BudgetAuthorityPortChirho for AuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, msg_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{msg_chirho}")
    }
}

fn signed_chirho(kind_chirho: BudgetEventKindChirho) -> BudgetEventAttestationChirho {
    let intent_chirho = BudgetEventIntentChirho {
        schema_chirho: BUDGET_EVENT_INTENT_SCHEMA_V2_CHIRHO.to_string(),
        evidence_root_key_id_chirho: ROOT_KEY_CHIRHO.to_string(),
        tenant_id_chirho: TENANT_CHIRHO.to_string(),
        budget_id_chirho: BUDGET_CHIRHO.to_string(),
        funding_record_digest_chirho: FUNDING_DIGEST_CHIRHO.to_string(),
        reservation_id_chirho: "reservation-1-chirho".to_string(),
        kind_chirho,
        event_seq_chirho: 1,
    };
    let mut record_chirho = BudgetEventAttestationChirho {
        schema_chirho: BUDGET_EVENT_ATTESTATION_SCHEMA_V2_CHIRHO.to_string(),
        signature_domain_chirho: BUDGET_EVENT_ATTESTATION_DOMAIN_V2_CHIRHO.to_string(),
        intent_digest_chirho: budget_event_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_budget_event_message_chirho(&record_chirho)
    );
    record_chirho
}

fn scope_chirho(budget_id_chirho: &str) -> BudgetEvidenceScopeChirho {
    BudgetEvidenceScopeChirho {
        evidence_root_key_id_chirho: ROOT_KEY_CHIRHO.to_string(),
        tenant_id_chirho: TENANT_CHIRHO.to_string(),
        budget_id_chirho: budget_id_chirho.to_string(),
    }
}

fn verify_chirho(
    record_chirho: &BudgetEventAttestationChirho,
    budget_id_chirho: &str,
) -> Result<VerifiedBudgetEventChirho, BudgetEventRefusalChirho> {
    verify_budget_event_chirho(
        record_chirho,
        &AuthorityChirho,
        &scope_chirho(budget_id_chirho),
        FUNDING_DIGEST_CHIRHO,
    )
}

fn reserve_chirho() -> BudgetEventAttestationChirho {
    signed_chirho(BudgetEventKindChirho::ReserveChirho {
        requested_micros_chirho: 5_000,
        deadline_millis_chirho: 10_000,
    })
}

#[test]
fn a_correctly_signed_event_verifies_chirho() {
    // Positive control: without it every refusal below would pass against a verifier that refused
    // everything, which is the failure mode a file of negative arms invites.
    let verified_chirho = verify_chirho(&reserve_chirho(), BUDGET_CHIRHO)
        .expect("a correctly signed event must verify");
    assert_eq!(verified_chirho.budget_id_chirho(), BUDGET_CHIRHO);
    assert_eq!(verified_chirho.event_seq_chirho(), 1);
}

#[test]
fn a_self_reported_digest_is_not_trusted_chirho() {
    // THE arm. The record carries its own digest AND a signature over it. Believing the declared
    // digest means checking a signature over a number the record chose, while the intent underneath
    // says whatever its author wanted — here, a reservation ten thousand times larger.
    let honest_chirho = reserve_chirho();
    let mut forged_chirho = honest_chirho.clone();
    forged_chirho.intent_chirho.kind_chirho = BudgetEventKindChirho::ReserveChirho {
        requested_micros_chirho: 50_000_000,
        deadline_millis_chirho: 10_000,
    };
    // Digest and signature left as they were: consistent with each other, wrong for the intent.
    let refusal_chirho = verify_chirho(&forged_chirho, BUDGET_CHIRHO)
        .expect_err("an intent that does not match its digest must refuse");
    assert!(
        matches!(
            refusal_chirho,
            BudgetEventRefusalChirho::IntentDigestMismatchChirho { .. }
        ),
        "must refuse on the RECOMPUTED digest, not on the signature: {refusal_chirho:?}"
    );
}

#[test]
fn an_unknown_key_refuses_as_an_unknown_key_not_a_bad_signature_chirho() {
    // Ordering: key BEFORE signature. Collapsing them tells an operator to go hunting for a signing
    // bug when the real answer is that this verifier does not speak for that authority.
    let mut record_chirho = reserve_chirho();
    record_chirho.authority_key_id_chirho = "someone-elses-key-chirho".to_string();
    assert!(matches!(
        verify_chirho(&record_chirho, BUDGET_CHIRHO).expect_err("unknown key"),
        BudgetEventRefusalChirho::UnknownAuthorityKeyChirho { .. }
    ));
}

#[test]
fn a_bad_signature_refuses_chirho() {
    let mut record_chirho = reserve_chirho();
    record_chirho.sig_chirho = "sig-over:something-else-chirho".to_string();
    assert_eq!(
        verify_chirho(&record_chirho, BUDGET_CHIRHO).expect_err("bad signature"),
        BudgetEventRefusalChirho::BadSignatureChirho
    );
}

#[test]
fn an_event_for_another_budget_refuses_chirho() {
    // A perfectly valid event, signed by the right authority, for a DIFFERENT budget. Without this
    // binding one budget's authority moves another's credits.
    assert!(matches!(
        verify_chirho(&reserve_chirho(), "budget-b-chirho").expect_err("wrong budget"),
        BudgetEventRefusalChirho::BudgetMismatchChirho { .. }
    ));
}

#[test]
fn an_event_for_another_evidence_root_refuses_after_authentication_chirho() {
    let record_chirho = reserve_chirho();
    let foreign_scope_chirho = BudgetEvidenceScopeChirho {
        evidence_root_key_id_chirho: "root-key-b-chirho".to_string(),
        tenant_id_chirho: TENANT_CHIRHO.to_string(),
        budget_id_chirho: BUDGET_CHIRHO.to_string(),
    };
    assert!(matches!(
        verify_budget_event_chirho(
            &record_chirho,
            &AuthorityChirho,
            &foreign_scope_chirho,
            FUNDING_DIGEST_CHIRHO,
        )
        .expect_err("foreign evidence root"),
        BudgetEventRefusalChirho::EvidenceRootMismatchChirho { .. }
    ));
}

#[test]
fn a_zero_reservation_refuses_chirho() {
    // Reserves nothing, resolves to nothing — a mistake rather than an intention, kept out of an
    // append-only log where it would sit forever meaning nothing.
    let record_chirho = signed_chirho(BudgetEventKindChirho::ReserveChirho {
        requested_micros_chirho: 0,
        deadline_millis_chirho: 10_000,
    });
    assert_eq!(
        verify_chirho(&record_chirho, BUDGET_CHIRHO).expect_err("zero reservation"),
        BudgetEventRefusalChirho::ZeroReservationChirho
    );
}

#[test]
fn a_zero_settlement_is_allowed_because_it_means_something_chirho() {
    // Deliberately NOT symmetric with the zero-reserve refusal: settling zero says "it succeeded and
    // consumed nothing", which is a real outcome, and the whole reservation returns. Refusing it would
    // force a caller to misreport a free success as a failure.
    let record_chirho = signed_chirho(BudgetEventKindChirho::SettleChirho {
        settled_micros_chirho: 0,
    });
    assert!(verify_chirho(&record_chirho, BUDGET_CHIRHO).is_ok());
}

#[test]
fn an_over_long_field_refuses_by_name_chirho() {
    let mut record_chirho = reserve_chirho();
    record_chirho.intent_chirho.reservation_id_chirho =
        "r".repeat(MAX_BUDGET_TOKEN_BYTES_CHIRHO + 1);
    record_chirho.intent_digest_chirho =
        budget_event_intent_digest_chirho(&record_chirho.intent_chirho).expect("digest");
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_budget_event_message_chirho(&record_chirho)
    );
    assert_eq!(
        verify_chirho(&record_chirho, BUDGET_CHIRHO).expect_err("over-long field"),
        BudgetEventRefusalChirho::FieldTooLongChirho {
            field_chirho: "reservation_id_chirho".to_string(),
        }
    );
}

#[test]
fn a_signature_bound_sized_for_a_token_would_refuse_every_real_signature_chirho() {
    // Positive control on the BOUNDS themselves. A bare ed25519 hex signature is exactly 128
    // characters, so one shared 128-byte limit would refuse every correct record — a mistake that the
    // negative arms above could never reveal, and that was caught this way once already.
    let mut record_chirho = reserve_chirho();
    record_chirho.sig_chirho = "a".repeat(128);
    assert!(
        !matches!(
            verify_chirho(&record_chirho, BUDGET_CHIRHO),
            Err(BudgetEventRefusalChirho::FieldTooLongChirho { .. })
        ),
        "a 128-character signature must pass the LENGTH check (it fails later, on the signature)"
    );
}
