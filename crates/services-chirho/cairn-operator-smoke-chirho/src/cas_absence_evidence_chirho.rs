// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Decides an operator-evidence "this raw body is not in public CAS" claim from genuine ABSENCE only.

use anyhow::{bail, Result};
use cairn_chirho::cas_chirho;
use cairn_chirho::model_chirho::HashChirho;
use std::path::Path;

/// Is the body at `address_chirho` PROVABLY not sitting in public CAS?
///
/// `Ok(true)` means the object path holds nothing — `NotFound` and nothing wider. `Ok(false)` means
/// the body is right there and verifies, so the caller's own refusal fires with its own wording.
///
/// The two remaining outcomes REFUSE rather than answer, because neither can support the claim:
///
/// * UNREADABLE is the privacy false negative this exists to remove. A mode-000 object file, or a
///   mode-000 shard directory, makes the read fail while the raw PII body may be sitting there
///   intact — so an `is_err()`-shaped probe records ABSENT over a body that is PRESENT, and that
///   sentence travels into shipped operator evidence and into the launch-readiness AND-chain.
/// * TAMPERED is the weaker case — bytes that do not re-hash to this address genuinely are not the
///   raw body — but it is still a store-integrity anomaly here: these smokes build their own fresh
///   root, so nothing legitimate writes wrong-hash bytes at exactly the address of the private
///   body. Evidence ABOUT an address is not worth producing from a store visibly corrupt AT that
///   address, so this refuses rather than quietly counting as absence.
pub(crate) fn raw_body_absent_from_public_cas_chirho(
    root_chirho: &Path,
    address_chirho: &HashChirho,
    surface_chirho: &str,
) -> Result<bool> {
    match cas_chirho::read_verified_chirho(root_chirho, address_chirho) {
        cas_chirho::CasReadOutcomeChirho::AbsentChirho(_absent_chirho) => Ok(true),
        cas_chirho::CasReadOutcomeChirho::VerifiedChirho(_present_chirho) => Ok(false),
        cas_chirho::CasReadOutcomeChirho::TamperedChirho { actual_chirho, .. } => bail!(
            "{surface_chirho}: public CAS holds tampered bytes at {} (they re-hash to {}), so \
             absence of the private body cannot be claimed from this store",
            address_chirho.0,
            actual_chirho.0
        ),
        cas_chirho::CasReadOutcomeChirho::UnreadableChirho(error_chirho) => bail!(
            "{surface_chirho}: public CAS object {} could not be read ({error_chirho}), so it is \
             not known to be absent — the raw body may be present",
            address_chirho.0
        ),
    }
}

#[cfg(test)]
#[path = "cas_absence_evidence_chirho/tests_chirho.rs"]
mod tests_chirho;

// The arms above prove THIS function. The arms below prove the two shipped callers still ask it.
#[cfg(test)]
#[path = "cas_absence_evidence_chirho/wiring_tests_chirho.rs"]
mod wiring_tests_chirho;
