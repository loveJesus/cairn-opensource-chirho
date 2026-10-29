// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Wire a verified conservation snapshot into the GD7 converger's conservation port, signed.
//!
//! This is the composition-root half of the B3b split. The host defines the port and MEASURES
//! conservation through the CF4 checker; it must not reach the journal. Only this crate links both
//! the audit derivation (`derive_conservation_snapshot_chirho`) and the checker, so only this crate
//! can turn a journal into a signed snapshot the converger will accept.
//!
//! Dependency note, recorded because a new edge should never land silently: this crate gained a
//! dependency on `cairn-ledger-host-chirho`. It is the composition-root direction — top-of-stack
//! constructs the converger with a concrete adapter — and it is acyclic: the host depends only on
//! leafward crates and never on this one.
//!
//! The signer is the node's GD7 control-plane signer, so the snapshot carries the same identity as
//! the reconciliation records it will be certified alongside. The adapter can only ATTEST what the
//! inner port derived; it cannot make an unbalanced snapshot pass, because the converger runs the
//! equations after checking the signature.

use cairn_ledger_conservation_monitor_chirho::ports_chirho::VerifiedConservationSnapshotPortChirho;
use cairn_ledger_host_chirho::reconciliation_chirho::{
    gd7_conservation_snapshot_signed_content_line_chirho, Gd7ConservationSnapshotSourcePortChirho,
    Gd7ConservationSnapshotVerifierPortChirho, Gd7PlanRefusalChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
    SignedGd7ConservationSnapshotChirho,
};

/// Signs whatever snapshot the inner verified-view port returns.
///
/// The inner port owes the monitor port's contract (verify sources, one signed cut, fail closed).
/// Its error type is deliberately collapsed to a single fail-closed refusal here: the converger's
/// only correct response to "no verified snapshot" is to refuse, and the detail belongs in the
/// source's own logs rather than in a certificate-path refusal.
pub struct Gd7SignedConservationSnapshotSourceChirho<'ports_chirho, SourceChirho> {
    pub snapshot_source_chirho: SourceChirho,
    pub signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
}

impl<SourceChirho> Gd7ConservationSnapshotSourcePortChirho
    for Gd7SignedConservationSnapshotSourceChirho<'_, SourceChirho>
where
    SourceChirho: VerifiedConservationSnapshotPortChirho,
{
    fn load_signed_conservation_snapshot_chirho(
        &self,
    ) -> Result<SignedGd7ConservationSnapshotChirho, Gd7PlanRefusalChirho> {
        let snapshot_chirho = self
            .snapshot_source_chirho
            .load_verified_head_consistent_snapshot_chirho()
            .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let content_line_chirho =
            gd7_conservation_snapshot_signed_content_line_chirho(&snapshot_chirho)?;
        let sig_chirho = self
            .signer_chirho
            .sign_chirho(&content_line_chirho)
            .map_err(|_| Gd7PlanRefusalChirho::SigningChirho)?;
        Ok(SignedGd7ConservationSnapshotChirho {
            snapshot_chirho,
            key_id_chirho: self.signer_chirho.key_id_chirho(),
            sig_chirho,
        })
    }
}

/// Presents the node's GD7 control-plane verification root as the conservation snapshot verifier.
///
/// Kept as its own type rather than folded into the source: a port that both supplies bytes and
/// vouches for them could verify its own tampering.
pub struct Gd7ReconciliationKeyConservationVerifierChirho<'ports_chirho> {
    pub verifier_chirho: &'ports_chirho dyn Gd7ReconciliationVerifierPortChirho,
}

impl Gd7ConservationSnapshotVerifierPortChirho
    for Gd7ReconciliationKeyConservationVerifierChirho<'_>
{
    fn key_id_chirho(&self) -> String {
        self.verifier_chirho.key_id_chirho()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.verifier_chirho
            .verify_chirho(canonical_unsigned_chirho, sig_chirho)
    }
}
