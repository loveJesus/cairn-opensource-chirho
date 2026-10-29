// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;

const KEY_CHIRHO: &str = "budget-authority-key-chirho";

struct AuthorityChirho;

impl BudgetAuthorityPortChirho for AuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        KEY_CHIRHO.to_string()
    }

    fn verify_chirho(&self, message_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{message_chirho}")
    }
}

fn scope_chirho() -> BudgetEvidenceScopeChirho {
    BudgetEvidenceScopeChirho {
        evidence_root_key_id_chirho: "root-key-a-chirho".to_string(),
        tenant_id_chirho: "tenant-a-chirho".to_string(),
        budget_id_chirho: "budget-a-chirho".to_string(),
    }
}

fn funding_chirho(ceiling_chirho: u64) -> BudgetFundingAttestationChirho {
    let scope_chirho = scope_chirho();
    let intent_chirho = BudgetFundingIntentChirho {
        schema_chirho: BUDGET_FUNDING_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        evidence_root_key_id_chirho: scope_chirho.evidence_root_key_id_chirho,
        tenant_id_chirho: scope_chirho.tenant_id_chirho,
        budget_id_chirho: scope_chirho.budget_id_chirho,
        prepaid_ceiling_micros_chirho: ceiling_chirho,
    };
    let mut record_chirho = BudgetFundingAttestationChirho {
        schema_chirho: BUDGET_FUNDING_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: BUDGET_FUNDING_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: budget_funding_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_budget_funding_message_chirho(&record_chirho)
    );
    record_chirho
}

#[test]
fn signed_scalar_funding_verifies_with_its_provenance_chirho() {
    let record_chirho = funding_chirho(100_000);
    let verified_chirho =
        verify_budget_funding_chirho(&record_chirho, &AuthorityChirho, &scope_chirho())
            .expect("verified funding");
    assert_eq!(verified_chirho.prepaid_ceiling_micros_chirho(), 100_000);
    assert_eq!(
        verified_chirho.record_digest_chirho(),
        budget_funding_record_digest_chirho(&record_chirho).expect("record digest")
    );
}

#[test]
fn caller_inflation_without_a_new_signature_refuses_chirho() {
    let mut record_chirho = funding_chirho(100_000);
    record_chirho.intent_chirho.prepaid_ceiling_micros_chirho = 1_000_000;
    assert!(matches!(
        verify_budget_funding_chirho(&record_chirho, &AuthorityChirho, &scope_chirho()),
        Err(BudgetFundingRefusalChirho::IntentDigestMismatchChirho { .. })
    ));
}

#[test]
fn funding_for_another_root_refuses_by_scope_not_signature_chirho() {
    let record_chirho = funding_chirho(100_000);
    let mut other_scope_chirho = scope_chirho();
    other_scope_chirho.evidence_root_key_id_chirho = "root-key-b-chirho".to_string();
    assert!(matches!(
        verify_budget_funding_chirho(&record_chirho, &AuthorityChirho, &other_scope_chirho),
        Err(BudgetFundingRefusalChirho::EvidenceRootMismatchChirho { .. })
    ));
}
