// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Budget movements as signed EVIDENCE rather than as calls.
//!
//! `infrastructure_budget_chirho` next door is the rule; it has no idea who asked. That is fine while
//! a budget lives in one process, and it is exactly the gap CF8's audit names for clause 11 — *signed
//! principals/evidence, durable adapters, and production callers rather than caller-supplied in-memory
//! values*. A reservation that anyone may author is not a prepaid ceiling; it is a suggestion.
//!
//! **Verify-only, with no `sign_chirho` on the port.** The party whose spending is bounded must not be
//! able to author the evidence that bounds it — the same reason capacity is registrar-signed and a
//! topology grant is bound to a principal it does not hold.
//!
//! **What this layer does NOT do, stated because the boundary is easy to blur.** It does not decide
//! whether a reservation fits the ceiling, or whether a settlement exceeds its reservation, or whether
//! a deadline has passed. Those are the RULE's job and it already refuses them by name. This layer
//! answers one question — *did the budget authority actually say this* — and a caller that treats a
//! verified event as an authorized outcome has skipped the rule.
//!
//! One intent-specific refusal the envelope shape cannot give: a RESERVE of zero. It reserves nothing
//! and would resolve to nothing, so it is a mistake rather than an intention, and catching it here
//! keeps a meaningless row out of an append-only log.

pub use super::budget_funding_attestation_chirho::{
    BudgetAuthorityPortChirho, BudgetEvidenceScopeChirho,
};
use cairn_core_chirho::store_chirho::hash_object_chirho;
use serde::{Deserialize, Serialize};

pub const BUDGET_EVENT_INTENT_SCHEMA_V2_CHIRHO: &str = "cairn.budget-event-intent.v2.chirho";
pub const BUDGET_EVENT_ATTESTATION_SCHEMA_V2_CHIRHO: &str =
    "cairn.budget-event-attestation.v2.chirho";
pub const BUDGET_EVENT_ATTESTATION_DOMAIN_V2_CHIRHO: &str =
    "cairn.budget-event-attestation.v2.signature.chirho";

/// Bounds on free-form tokens. A signature needs its own, larger bound: a bare ed25519 hex signature
/// is exactly 128 characters, so a single 128-byte limit for every field would refuse every correct
/// record — a positive control caught precisely that on the capacity envelope.
pub const MAX_BUDGET_TOKEN_BYTES_CHIRHO: usize = 128;
pub const MAX_BUDGET_SIGNATURE_BYTES_CHIRHO: usize = 512;

/// What this event does to one reservation. Terminal kinds are mutually exclusive by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetEventKindChirho {
    /// Claim a priced maximum BEFORE provisioning.
    ReserveChirho {
        requested_micros_chirho: u64,
        deadline_millis_chirho: u64,
    },
    /// The provision succeeded and consumed this much; the remainder returns to the budget.
    SettleChirho { settled_micros_chirho: u64 },
    /// The provision failed or passed its deadline; the whole reservation returns.
    ReleaseChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetEventIntentChirho {
    pub schema_chirho: String,
    /// The evidence-root identity this event may enter. Copying a valid record to another root must
    /// fail even when both roots trust the same budget authority.
    pub evidence_root_key_id_chirho: String,
    pub tenant_id_chirho: String,
    /// Which budget this moves. Events for one budget must not resolve against another.
    pub budget_id_chirho: String,
    /// The immutable signed funding record whose scalar ceiling this event consumes.
    pub funding_record_digest_chirho: String,
    pub reservation_id_chirho: String,
    pub kind_chirho: BudgetEventKindChirho,
    /// Monotone per budget. The verifier is STATELESS and cannot check it; the durable store keeps the
    /// high-water mark, exactly as the capacity and grant stores do for theirs.
    pub event_seq_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetEventAttestationChirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub intent_chirho: BudgetEventIntentChirho,
    pub intent_digest_chirho: String,
    pub authority_key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetEventRefusalChirho {
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
    /// The record names an authority this verifier does not speak for. Checked BEFORE the signature,
    /// so an unknown key refuses as an unknown key rather than as a bad signature.
    UnknownAuthorityKeyChirho {
        found_chirho: String,
    },
    /// The record's self-reported digest is not the digest of its own intent.
    IntentDigestMismatchChirho {
        declared_chirho: String,
        recomputed_chirho: String,
    },
    BadSignatureChirho,
    /// This event is for a different budget than the one being loaded.
    BudgetMismatchChirho {
        expected_chirho: String,
        found_chirho: String,
    },
    EvidenceRootMismatchChirho {
        expected_chirho: String,
        found_chirho: String,
    },
    TenantMismatchChirho {
        expected_chirho: String,
        found_chirho: String,
    },
    FundingDigestMismatchChirho {
        expected_chirho: String,
        found_chirho: String,
    },
    /// A reservation of zero reserves nothing and resolves to nothing.
    ZeroReservationChirho,
}

/// A budget event that verified. Obtainable only through [`verify_budget_event_chirho`], so holding
/// one IS the evidence that the authority said it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBudgetEventChirho {
    intent_chirho: BudgetEventIntentChirho,
}

/// An authentic event whose signed routing fields have not yet been bound to trusted store context.
/// Keeping this separate prevents a loader from using an unverified budget id to choose a funding
/// record while also preventing authenticity alone from being mistaken for admission authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedBudgetEventChirho {
    intent_chirho: BudgetEventIntentChirho,
}

impl AuthenticatedBudgetEventChirho {
    pub fn budget_id_chirho(&self) -> &str {
        &self.intent_chirho.budget_id_chirho
    }
}

impl VerifiedBudgetEventChirho {
    pub fn budget_id_chirho(&self) -> &str {
        &self.intent_chirho.budget_id_chirho
    }
    pub fn reservation_id_chirho(&self) -> &str {
        &self.intent_chirho.reservation_id_chirho
    }
    pub fn kind_chirho(&self) -> BudgetEventKindChirho {
        self.intent_chirho.kind_chirho
    }
    pub fn event_seq_chirho(&self) -> u64 {
        self.intent_chirho.event_seq_chirho
    }

    pub fn funding_record_digest_chirho(&self) -> &str {
        &self.intent_chirho.funding_record_digest_chirho
    }
}

pub fn budget_event_intent_digest_chirho(
    intent_chirho: &BudgetEventIntentChirho,
) -> Result<String, BudgetEventRefusalChirho> {
    hash_object_chirho(intent_chirho)
        .map(|hash_chirho| hash_chirho.0)
        .map_err(|_error_chirho| BudgetEventRefusalChirho::BadSignatureChirho)
}

/// The exact bytes signed. Deliberately NOT unified with the other envelopes' message builders: each
/// one names its own domain and fields, and a shared builder would let a record signed for one
/// purpose verify for another.
pub fn unsigned_budget_event_message_chirho(
    record_chirho: &BudgetEventAttestationChirho,
) -> String {
    format!(
        "{}|{}|{}|{}",
        record_chirho.signature_domain_chirho,
        record_chirho.schema_chirho,
        record_chirho.authority_key_id_chirho,
        record_chirho.intent_digest_chirho
    )
}

/// Order: shape, bounds, KEY, recomputed digest, signature, then intent-specific bindings.
///
/// The key is checked before the signature so an unknown authority refuses as one. The digest is
/// RECOMPUTED rather than trusted — a record that carries its own digest and is believed has a
/// signature over a number it chose.
pub fn verify_budget_event_chirho(
    record_chirho: &BudgetEventAttestationChirho,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
    expected_scope_chirho: &BudgetEvidenceScopeChirho,
    expected_funding_record_digest_chirho: &str,
) -> Result<VerifiedBudgetEventChirho, BudgetEventRefusalChirho> {
    bind_authenticated_budget_event_chirho(
        authenticate_budget_event_chirho(record_chirho, authority_chirho)?,
        expected_scope_chirho,
        expected_funding_record_digest_chirho,
    )
}

/// Verify shape, digest, authority key and signature before any signed routing field is consumed.
pub fn authenticate_budget_event_chirho(
    record_chirho: &BudgetEventAttestationChirho,
    authority_chirho: &dyn BudgetAuthorityPortChirho,
) -> Result<AuthenticatedBudgetEventChirho, BudgetEventRefusalChirho> {
    if record_chirho.schema_chirho != BUDGET_EVENT_ATTESTATION_SCHEMA_V2_CHIRHO {
        return Err(BudgetEventRefusalChirho::RecordSchemaMismatchChirho {
            found_chirho: record_chirho.schema_chirho.clone(),
        });
    }
    if record_chirho.intent_chirho.schema_chirho != BUDGET_EVENT_INTENT_SCHEMA_V2_CHIRHO {
        return Err(BudgetEventRefusalChirho::IntentSchemaMismatchChirho {
            found_chirho: record_chirho.intent_chirho.schema_chirho.clone(),
        });
    }
    if record_chirho.signature_domain_chirho != BUDGET_EVENT_ATTESTATION_DOMAIN_V2_CHIRHO {
        return Err(BudgetEventRefusalChirho::SignatureDomainMismatchChirho {
            found_chirho: record_chirho.signature_domain_chirho.clone(),
        });
    }
    for (field_chirho, value_chirho, bound_chirho) in [
        (
            "evidence_root_key_id_chirho",
            &record_chirho.intent_chirho.evidence_root_key_id_chirho,
            MAX_BUDGET_TOKEN_BYTES_CHIRHO,
        ),
        (
            "tenant_id_chirho",
            &record_chirho.intent_chirho.tenant_id_chirho,
            MAX_BUDGET_TOKEN_BYTES_CHIRHO,
        ),
        (
            "budget_id_chirho",
            &record_chirho.intent_chirho.budget_id_chirho,
            MAX_BUDGET_TOKEN_BYTES_CHIRHO,
        ),
        (
            "funding_record_digest_chirho",
            &record_chirho.intent_chirho.funding_record_digest_chirho,
            MAX_BUDGET_TOKEN_BYTES_CHIRHO,
        ),
        (
            "reservation_id_chirho",
            &record_chirho.intent_chirho.reservation_id_chirho,
            MAX_BUDGET_TOKEN_BYTES_CHIRHO,
        ),
        (
            "authority_key_id_chirho",
            &record_chirho.authority_key_id_chirho,
            MAX_BUDGET_TOKEN_BYTES_CHIRHO,
        ),
        (
            "intent_digest_chirho",
            &record_chirho.intent_digest_chirho,
            MAX_BUDGET_TOKEN_BYTES_CHIRHO,
        ),
        (
            "sig_chirho",
            &record_chirho.sig_chirho,
            MAX_BUDGET_SIGNATURE_BYTES_CHIRHO,
        ),
    ] {
        if value_chirho.len() > bound_chirho {
            return Err(BudgetEventRefusalChirho::FieldTooLongChirho {
                field_chirho: field_chirho.to_string(),
            });
        }
    }
    if record_chirho.authority_key_id_chirho != authority_chirho.authority_key_id_chirho() {
        return Err(BudgetEventRefusalChirho::UnknownAuthorityKeyChirho {
            found_chirho: record_chirho.authority_key_id_chirho.clone(),
        });
    }
    let recomputed_chirho = budget_event_intent_digest_chirho(&record_chirho.intent_chirho)?;
    if recomputed_chirho != record_chirho.intent_digest_chirho {
        return Err(BudgetEventRefusalChirho::IntentDigestMismatchChirho {
            declared_chirho: record_chirho.intent_digest_chirho.clone(),
            recomputed_chirho,
        });
    }
    if !authority_chirho.verify_chirho(
        &unsigned_budget_event_message_chirho(record_chirho),
        &record_chirho.sig_chirho,
    ) {
        return Err(BudgetEventRefusalChirho::BadSignatureChirho);
    }
    if let BudgetEventKindChirho::ReserveChirho {
        requested_micros_chirho,
        ..
    } = record_chirho.intent_chirho.kind_chirho
    {
        if requested_micros_chirho == 0 {
            return Err(BudgetEventRefusalChirho::ZeroReservationChirho);
        }
    }
    Ok(AuthenticatedBudgetEventChirho {
        intent_chirho: record_chirho.intent_chirho.clone(),
    })
}

/// Bind an already-authenticated event to trusted root, tenant, budget and funding coordinates.
pub fn bind_authenticated_budget_event_chirho(
    event_chirho: AuthenticatedBudgetEventChirho,
    expected_scope_chirho: &BudgetEvidenceScopeChirho,
    expected_funding_record_digest_chirho: &str,
) -> Result<VerifiedBudgetEventChirho, BudgetEventRefusalChirho> {
    if event_chirho.intent_chirho.evidence_root_key_id_chirho
        != expected_scope_chirho.evidence_root_key_id_chirho
    {
        return Err(BudgetEventRefusalChirho::EvidenceRootMismatchChirho {
            expected_chirho: expected_scope_chirho.evidence_root_key_id_chirho.clone(),
            found_chirho: event_chirho
                .intent_chirho
                .evidence_root_key_id_chirho
                .clone(),
        });
    }
    if event_chirho.intent_chirho.tenant_id_chirho != expected_scope_chirho.tenant_id_chirho {
        return Err(BudgetEventRefusalChirho::TenantMismatchChirho {
            expected_chirho: expected_scope_chirho.tenant_id_chirho.clone(),
            found_chirho: event_chirho.intent_chirho.tenant_id_chirho.clone(),
        });
    }
    if event_chirho.intent_chirho.budget_id_chirho != expected_scope_chirho.budget_id_chirho {
        return Err(BudgetEventRefusalChirho::BudgetMismatchChirho {
            expected_chirho: expected_scope_chirho.budget_id_chirho.clone(),
            found_chirho: event_chirho.intent_chirho.budget_id_chirho.clone(),
        });
    }
    if event_chirho.intent_chirho.funding_record_digest_chirho
        != expected_funding_record_digest_chirho
    {
        return Err(BudgetEventRefusalChirho::FundingDigestMismatchChirho {
            expected_chirho: expected_funding_record_digest_chirho.to_string(),
            found_chirho: event_chirho
                .intent_chirho
                .funding_record_digest_chirho
                .clone(),
        });
    }
    Ok(VerifiedBudgetEventChirho {
        intent_chirho: event_chirho.intent_chirho,
    })
}

#[cfg(test)]
#[path = "budget_event_attestation_tests_chirho.rs"]
mod budget_event_attestation_tests_chirho;
