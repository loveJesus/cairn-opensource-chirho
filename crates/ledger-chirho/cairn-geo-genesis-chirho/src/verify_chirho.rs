// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The custody-pinned plan verifier (design section 10): the exact verify order that turns candidate
//! bytes into a private `VerifiedGeoGenesisPlanChirho` token — parse, ruled-combination, custody-pin
//! match, signature verification against the externally pinned key, byte-identical canonical
//! re-encode, a REAL inward-edge reload of the ledger regenesis plan digest, and freshness. Item-5/6/7
//! evidence refs stay contract-digest stubs until 8.7; the durable one-time guard is 8.2c.

use crate::codec_chirho::{canonical_blake3_hex_chirho, canonical_record_bytes_chirho};
use crate::digest_chirho::{GeoGenesisPlanDigestChirho, GeoLedgerRegenesisPlanDigestChirho};
use crate::error_chirho::{GeoGenesisRefusalChirho, GeoGenesisResultChirho};
use crate::metadata_chirho::GeoGgVerdictChirho;
use crate::plan_chirho::{parse_canonical_plan_chirho, GeoGenesisPlanV1Chirho};
use crate::ruling_chirho::{GeoGenesisTrustProfileChirho, GeoGg6OrderingRulingChirho};
use crate::scalar_chirho::GeoEd25519PublicKeyChirho;
use crate::trust_chirho::{
    curve_point_verifying_key_chirho, verify_class_signature_chirho, GeoGenesisMessageClassChirho,
    GeoGenesisTrustPinsChirho, GeoSignerRoleChirho,
};
use cairn_ledger_regenesis_chirho::LedgerRegenesisPlanV1Chirho;

/// A plan that passed the full section-10 verify order under a specific set of custody pins. Its
/// fields are private and there is no public constructor, so a caller cannot fabricate a "verified"
/// plan; the only way to obtain one is through `verify_plan_chirho`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGeoGenesisPlanChirho {
    plan_chirho: GeoGenesisPlanV1Chirho,
    plan_digest_chirho: GeoGenesisPlanDigestChirho,
    canonical_bytes_chirho: Vec<u8>,
}

impl VerifiedGeoGenesisPlanChirho {
    /// The verified plan.
    pub fn plan_chirho(&self) -> &GeoGenesisPlanV1Chirho {
        &self.plan_chirho
    }

    /// The blake3 digest of the verified canonical plan bytes.
    pub fn plan_digest_chirho(&self) -> GeoGenesisPlanDigestChirho {
        self.plan_digest_chirho
    }

    /// The exact canonical bytes that were verified.
    pub fn canonical_bytes_chirho(&self) -> &[u8] {
        &self.canonical_bytes_chirho
    }

    /// The custody-pinned plan-authority key that verified the plan signature.
    pub fn plan_signer_key_chirho(&self) -> GeoEd25519PublicKeyChirho {
        self.plan_chirho.plan_signer_key_chirho
    }
}

/// Enforce the ruled token combination (coordinator ruling 5). The types keep every option
/// representable; the ruling is carried here by validation: the trust profile must be the ruled split
/// authority, GG6 ordering must be the ruled phase split, and the GG6 disposition verdict must be the
/// wiring-ready verdict consistent with that ordering (design section 5.2).
pub(crate) fn enforce_ruled_combination_chirho(
    plan_chirho: &GeoGenesisPlanV1Chirho,
) -> GeoGenesisResultChirho<()> {
    if plan_chirho.trust_profile_chirho
        != GeoGenesisTrustProfileChirho::SplitDedicatedPlanAndAcceptanceAuthoritiesChirho
    {
        return Err(GeoGenesisRefusalChirho::RuledTrustProfileRefusedChirho);
    }
    if plan_chirho.rulings_chirho.gg6_ordering_chirho
        != GeoGg6OrderingRulingChirho::WiringReadyThenHostedAcceptedChirho
    {
        return Err(GeoGenesisRefusalChirho::RuledGg6OrderingRefusedChirho);
    }
    if plan_chirho.gg_dispositions_chirho.gg6_chirho.verdict_chirho
        != GeoGgVerdictChirho::VerifiedWiringReadyChirho
    {
        return Err(GeoGenesisRefusalChirho::Gg6VerdictOrderingMismatchChirho);
    }
    Ok(())
}

/// Curve-point-validate the plan's embedded Ed25519 keys (design section 5.4: node keys must decode
/// as one Ed25519 key). The plan-authority signer key, every member node key, and every member
/// custody key must be valid curve points; a 32-byte value that is not on the curve refuses. The
/// member custody key is carried, never used to verify a signature here, so its curve check is a
/// structural-consistency guarantee alongside the node key; the custody-DOMAIN non-equivalence
/// predicate over separately signed attestations stays the 8.2b `custody_chirho` predicate.
pub(crate) fn validate_plan_curve_points_chirho(
    plan_chirho: &GeoGenesisPlanV1Chirho,
) -> GeoGenesisResultChirho<()> {
    curve_point_verifying_key_chirho(&plan_chirho.plan_signer_key_chirho)?;
    for member_chirho in &plan_chirho.topology_chirho.members_chirho {
        curve_point_verifying_key_chirho(&member_chirho.node_key_chirho)?;
        curve_point_verifying_key_chirho(&member_chirho.custody_chirho.custody_key_chirho)?;
    }
    Ok(())
}

/// The full semantic gate the plan-authority path must pass, shared by authoring and verifying
/// (design section 10: authoring performs the same semantic verification before signing). Structural
/// validity, resolved rulings/trust profile, the ruled token combination, and Ed25519 curve-point
/// validation of the embedded keys. This does NOT verify a signature or reload the ledger plan; those
/// are separate ordered steps.
pub(crate) fn validate_plan_authority_semantics_chirho(
    plan_chirho: &GeoGenesisPlanV1Chirho,
) -> GeoGenesisResultChirho<()> {
    plan_chirho.validate_authorable_chirho()?;
    enforce_ruled_combination_chirho(plan_chirho)?;
    validate_plan_curve_points_chirho(plan_chirho)
}

/// Recompute the ledger regenesis plan digest through the REAL inward edge (the ledger-regenesis
/// crate's own canonical bytes + digest) and require it to equal the plan's bound digest. This is the
/// section-10 step-6 authoritative reload for the one artifact whose loader already exists; in
/// production the reviewed plan is reloaded from custody-verified storage (8.7), and here it is the
/// in-memory reviewed plan the operator supplies. Item-5/6/7 evidence refs remain contract-digest
/// stubs whose live loaders bind at 8.7.
pub(crate) fn reload_and_bind_ledger_plan_chirho(
    plan_chirho: &GeoGenesisPlanV1Chirho,
    reviewed_ledger_plan_chirho: &LedgerRegenesisPlanV1Chirho,
) -> GeoGenesisResultChirho<()> {
    let derived_chirho =
        GeoLedgerRegenesisPlanDigestChirho::from_canonical_ledger_regenesis_plan_chirho(
            reviewed_ledger_plan_chirho,
        )?;
    if derived_chirho != plan_chirho.ledger_chirho.ledger_regenesis_plan_chirho {
        return Err(GeoGenesisRefusalChirho::LedgerPlanDigestMismatchChirho);
    }
    Ok(())
}

/// Verify candidate plan bytes against the custody pins and the reviewed ledger plan, in the exact
/// section-10 order, returning a private verified token. No `--force`/`--ignore-stale`/caller-signer
/// override exists; the expected key comes only from the pins, never from the artifact.
pub fn verify_plan_chirho(
    candidate_bytes_chirho: &[u8],
    pins_chirho: &GeoGenesisTrustPinsChirho,
    reviewed_ledger_plan_chirho: &LedgerRegenesisPlanV1Chirho,
) -> GeoGenesisResultChirho<VerifiedGeoGenesisPlanChirho> {
    // Steps 1-3: bounded read is the caller's (8.3 custody); here parse with unknown/duplicate refused,
    // require the canonical encoding, run structural validation, then resolved rulings and the ruled
    // token combination (schema/enum/sort/uniqueness/bounds/equations).
    let plan_chirho = parse_canonical_plan_chirho(candidate_bytes_chirho)?;
    validate_plan_authority_semantics_chirho(&plan_chirho)?;

    // The custody-pinned plan-authority key is what verifies; the plan's embedded key must equal it,
    // never self-select the verifier. (Split pins always carry a plan-authority key.)
    let expected_key_chirho = pins_chirho
        .expected_authority_key_chirho(GeoSignerRoleChirho::PlanAuthorityChirho)
        .ok_or(GeoGenesisRefusalChirho::TrustPinsRefusedChirho)?;
    if plan_chirho.plan_signer_key_chirho != expected_key_chirho {
        return Err(GeoGenesisRefusalChirho::CustodyPinMismatchChirho);
    }

    // Step 4: build the explicit unsigned object and verify the signature against the externally
    // pinned key over the Plan message class (the key is curve-validated inside).
    let unsigned_bytes_chirho = canonical_record_bytes_chirho(&plan_chirho.to_unsigned_chirho())?;
    verify_class_signature_chirho(
        &expected_key_chirho,
        GeoGenesisMessageClassChirho::PlanChirho,
        &unsigned_bytes_chirho,
        &plan_chirho.signature_chirho,
    )?;

    // Step 5: canonicalize the complete signed object and require byte-identical input.
    let canonical_bytes_chirho = plan_chirho.canonical_bytes_chirho()?;
    if canonical_bytes_chirho != candidate_bytes_chirho {
        return Err(GeoGenesisRefusalChirho::NotCanonicalChirho);
    }

    // Steps 6-7: reload the ledger regenesis plan through the real inward edge and require its digest
    // to match; item-5/6/7 evidence contracts remain digest stubs until 8.7. Freshness, hard-gates,
    // and phase (step 8) are enforced by type and by `validate_structural_chirho`; the durable
    // no-second-genesis gate is the separate 8.2c guard.
    reload_and_bind_ledger_plan_chirho(&plan_chirho, reviewed_ledger_plan_chirho)?;

    // Step 9: the private verified token.
    let plan_digest_chirho = GeoGenesisPlanDigestChirho::from_hex_chirho(
        &canonical_blake3_hex_chirho(&canonical_bytes_chirho),
    )?;
    Ok(VerifiedGeoGenesisPlanChirho {
        plan_chirho,
        plan_digest_chirho,
        canonical_bytes_chirho,
    })
}
