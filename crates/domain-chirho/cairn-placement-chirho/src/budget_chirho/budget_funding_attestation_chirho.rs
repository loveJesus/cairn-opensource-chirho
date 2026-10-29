// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Immutable signed funding for one infrastructure budget.
//!
//! A prepaid ceiling is authority, not caller context. The signed intent therefore binds one scalar
//! ceiling to the evidence-root key, tenant, and budget that may consume it. Funding never rotates in
//! place: changing the ceiling creates a new budget identity, so a previously valid higher ceiling
//! cannot be replayed after a reduction.

use cairn_core_chirho::store_chirho::hash_object_chirho;
use serde::{Deserialize, Serialize};

pub const BUDGET_FUNDING_INTENT_SCHEMA_V1_CHIRHO: &str = "cairn.budget-funding-intent.v1.chirho";
pub const BUDGET_FUNDING_ATTESTATION_SCHEMA_V1_CHIRHO: &str =
    "cairn.budget-funding-attestation.v1.chirho";
pub const BUDGET_FUNDING_ATTESTATION_DOMAIN_V1_CHIRHO: &str =
    "cairn.budget-funding-attestation.v1.signature.chirho";
pub const MAX_BUDGET_FUNDING_TOKEN_BYTES_CHIRHO: usize = 128;
pub const MAX_BUDGET_FUNDING_SIGNATURE_BYTES_CHIRHO: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetEvidenceScopeChirho {
    pub evidence_root_key_id_chirho: String,
    pub tenant_id_chirho: String,
    pub budget_id_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetFundingIntentChirho {
    pub schema_chirho: String,
    pub evidence_root_key_id_chirho: String,
    pub tenant_id_chirho: String,
    pub budget_id_chirho: String,
    pub prepaid_ceiling_micros_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetFundingAttestationChirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub intent_chirho: BudgetFundingIntentChirho,
    pub intent_digest_chirho: String,
    pub authority_key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetFundingRefusalChirho {
    RecordSchemaMismatchChirho {
        found_chirho: String,
    },
    IntentSchemaMismatchChirho {
        found_chirho: String,
    },
    SignatureDomainMismatchChirho {
        found_chirho: String,
    },
    FieldTooLongChirho {
        field_chirho: String,
    },
    UnknownAuthorityKeyChirho {
        found_chirho: String,
    },
    IntentDigestMismatchChirho {
        declared_chirho: String,
        recomputed_chirho: String,
    },
    BadSignatureChirho,
    EvidenceRootMismatchChirho {
        expected_chirho: String,
        found_chirho: String,
    },
    TenantMismatchChirho {
        expected_chirho: String,
        found_chirho: String,
    },
    BudgetMismatchChirho {
        expected_chirho: String,
        found_chirho: String,
    },
}

/// The verify-only authority boundary shared by funding and budget-event evidence.
pub trait BudgetAuthorityPortChirho {
    fn authority_key_id_chirho(&self) -> String;
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBudgetFundingChirho {
    intent_chirho: BudgetFundingIntentChirho,
    record_digest_chirho: String,
    authority_key_id_chirho: String,
}

impl VerifiedBudgetFundingChirho {
    pub fn budget_id_chirho(&self) -> &str {
        &self.intent_chirho.budget_id_chirho
    }

    pub fn prepaid_ceiling_micros_chirho(&self) -> u64 {
        self.intent_chirho.prepaid_ceiling_micros_chirho
    }

    pub fn record_digest_chirho(&self) -> &str {
        &self.record_digest_chirho
    }

    pub fn authority_key_id_chirho(&self) -> &str {
        &self.authority_key_id_chirho
    }
}

pub fn budget_funding_intent_digest_chirho(
    intent_chirho: &BudgetFundingIntentChirho,
) -> Result<String, BudgetFundingRefusalChirho> {
    hash_object_chirho(intent_chirho)
        .map(|hash_chirho| hash_chirho.0)
        .map_err(|_error_chirho| BudgetFundingRefusalChirho::BadSignatureChirho)
}

pub fn budget_funding_record_digest_chirho(
    record_chirho: &BudgetFundingAttestationChirho,
) -> Result<String, BudgetFundingRefusalChirho> {
    hash_object_chirho(record_chirho)
        .map(|hash_chirho| hash_chirho.0)
        .map_err(|_error_chirho| BudgetFundingRefusalChirho::BadSignatureChirho)
}

pub fn unsigned_budget_funding_message_chirho(
    record_chirho: &BudgetFundingAttestationChirho,
) -> String {
    format!(
        "{}|{}|{}|{}",
        record_chirho.signature_domain_chirho,
        record_chirho.schema_chirho,
        record_chirho.authority_key_id_chirho,
        record_chirho.intent_digest_chirho
    )
}

pub fn verify_budget_funding_chirho(
    record_chirho: &BudgetFundingAttestationChirho,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
    expected_scope_chirho: &BudgetEvidenceScopeChirho,
) -> Result<VerifiedBudgetFundingChirho, BudgetFundingRefusalChirho> {
    if record_chirho.schema_chirho != BUDGET_FUNDING_ATTESTATION_SCHEMA_V1_CHIRHO {
        return Err(BudgetFundingRefusalChirho::RecordSchemaMismatchChirho {
            found_chirho: record_chirho.schema_chirho.clone(),
        });
    }
    if record_chirho.intent_chirho.schema_chirho != BUDGET_FUNDING_INTENT_SCHEMA_V1_CHIRHO {
        return Err(BudgetFundingRefusalChirho::IntentSchemaMismatchChirho {
            found_chirho: record_chirho.intent_chirho.schema_chirho.clone(),
        });
    }
    if record_chirho.signature_domain_chirho != BUDGET_FUNDING_ATTESTATION_DOMAIN_V1_CHIRHO {
        return Err(BudgetFundingRefusalChirho::SignatureDomainMismatchChirho {
            found_chirho: record_chirho.signature_domain_chirho.clone(),
        });
    }
    for (field_chirho, value_chirho, bound_chirho) in [
        (
            "evidence_root_key_id_chirho",
            &record_chirho.intent_chirho.evidence_root_key_id_chirho,
            MAX_BUDGET_FUNDING_TOKEN_BYTES_CHIRHO,
        ),
        (
            "tenant_id_chirho",
            &record_chirho.intent_chirho.tenant_id_chirho,
            MAX_BUDGET_FUNDING_TOKEN_BYTES_CHIRHO,
        ),
        (
            "budget_id_chirho",
            &record_chirho.intent_chirho.budget_id_chirho,
            MAX_BUDGET_FUNDING_TOKEN_BYTES_CHIRHO,
        ),
        (
            "authority_key_id_chirho",
            &record_chirho.authority_key_id_chirho,
            MAX_BUDGET_FUNDING_TOKEN_BYTES_CHIRHO,
        ),
        (
            "intent_digest_chirho",
            &record_chirho.intent_digest_chirho,
            MAX_BUDGET_FUNDING_TOKEN_BYTES_CHIRHO,
        ),
        (
            "sig_chirho",
            &record_chirho.sig_chirho,
            MAX_BUDGET_FUNDING_SIGNATURE_BYTES_CHIRHO,
        ),
    ] {
        if value_chirho.len() > bound_chirho {
            return Err(BudgetFundingRefusalChirho::FieldTooLongChirho {
                field_chirho: field_chirho.to_string(),
            });
        }
    }
    if record_chirho.authority_key_id_chirho != authority_chirho.authority_key_id_chirho() {
        return Err(BudgetFundingRefusalChirho::UnknownAuthorityKeyChirho {
            found_chirho: record_chirho.authority_key_id_chirho.clone(),
        });
    }
    let recomputed_chirho = budget_funding_intent_digest_chirho(&record_chirho.intent_chirho)?;
    if recomputed_chirho != record_chirho.intent_digest_chirho {
        return Err(BudgetFundingRefusalChirho::IntentDigestMismatchChirho {
            declared_chirho: record_chirho.intent_digest_chirho.clone(),
            recomputed_chirho,
        });
    }
    if !authority_chirho.verify_chirho(
        &unsigned_budget_funding_message_chirho(record_chirho),
        &record_chirho.sig_chirho,
    ) {
        return Err(BudgetFundingRefusalChirho::BadSignatureChirho);
    }
    if record_chirho.intent_chirho.evidence_root_key_id_chirho
        != expected_scope_chirho.evidence_root_key_id_chirho
    {
        return Err(BudgetFundingRefusalChirho::EvidenceRootMismatchChirho {
            expected_chirho: expected_scope_chirho.evidence_root_key_id_chirho.clone(),
            found_chirho: record_chirho
                .intent_chirho
                .evidence_root_key_id_chirho
                .clone(),
        });
    }
    if record_chirho.intent_chirho.tenant_id_chirho != expected_scope_chirho.tenant_id_chirho {
        return Err(BudgetFundingRefusalChirho::TenantMismatchChirho {
            expected_chirho: expected_scope_chirho.tenant_id_chirho.clone(),
            found_chirho: record_chirho.intent_chirho.tenant_id_chirho.clone(),
        });
    }
    if record_chirho.intent_chirho.budget_id_chirho != expected_scope_chirho.budget_id_chirho {
        return Err(BudgetFundingRefusalChirho::BudgetMismatchChirho {
            expected_chirho: expected_scope_chirho.budget_id_chirho.clone(),
            found_chirho: record_chirho.intent_chirho.budget_id_chirho.clone(),
        });
    }
    Ok(VerifiedBudgetFundingChirho {
        intent_chirho: record_chirho.intent_chirho.clone(),
        record_digest_chirho: budget_funding_record_digest_chirho(record_chirho)?,
        authority_key_id_chirho: record_chirho.authority_key_id_chirho.clone(),
    })
}

#[cfg(test)]
#[path = "budget_funding_attestation_tests_chirho.rs"]
mod budget_funding_attestation_tests_chirho;
