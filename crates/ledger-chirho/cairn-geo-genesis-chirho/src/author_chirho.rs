// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The operator-only plan author (design section 5/10): sign a fully-formed candidate plan with the
//! pre-provisioned plan-authority key, after the same semantic verification the verifier performs. The
//! embedded signer key is set from the loaded key, never self-selected by the input, and the signature
//! is produced over the Plan message class — a signer of any other role refuses.

use crate::codec_chirho::canonical_record_bytes_chirho;
use crate::error_chirho::GeoGenesisResultChirho;
use crate::plan_chirho::GeoGenesisPlanV1Chirho;
use crate::trust_chirho::{GeoGenesisMessageClassChirho, GeoRoleSignerChirho};
use crate::verify_chirho::{
    reload_and_bind_ledger_plan_chirho, validate_plan_authority_semantics_chirho,
};
use cairn_ledger_regenesis_chirho::LedgerRegenesisPlanV1Chirho;

/// Author (sign) a candidate plan with the plan-authority signer. The candidate carries every plan
/// field, including a placeholder signature; this function overrides the embedded signer key with the
/// signer's own public key (so it can never be self-selected), runs the full plan-authority semantic
/// gate plus the real ledger-plan reload, signs the unsigned canonical bytes over the Plan class, and
/// returns the signed plan. A non-plan-authority signer refuses at the message-class admission gate.
pub fn author_plan_chirho(
    mut candidate_plan_chirho: GeoGenesisPlanV1Chirho,
    plan_authority_signer_chirho: &GeoRoleSignerChirho,
    reviewed_ledger_plan_chirho: &LedgerRegenesisPlanV1Chirho,
) -> GeoGenesisResultChirho<GeoGenesisPlanV1Chirho> {
    // The embedded signer key is the loaded key, not whatever the input carried.
    candidate_plan_chirho.plan_signer_key_chirho = plan_authority_signer_chirho.public_key_chirho();

    // The same semantic verification the verifier runs, before any signature exists.
    validate_plan_authority_semantics_chirho(&candidate_plan_chirho)?;
    reload_and_bind_ledger_plan_chirho(&candidate_plan_chirho, reviewed_ledger_plan_chirho)?;

    // Sign the explicit unsigned canonical bytes over the Plan class. Cross-role signing refuses here.
    let unsigned_bytes_chirho =
        canonical_record_bytes_chirho(&candidate_plan_chirho.to_unsigned_chirho())?;
    let signature_chirho = plan_authority_signer_chirho.sign_class_chirho(
        GeoGenesisMessageClassChirho::PlanChirho,
        &unsigned_bytes_chirho,
    )?;
    candidate_plan_chirho.signature_chirho = signature_chirho;
    Ok(candidate_plan_chirho)
}
