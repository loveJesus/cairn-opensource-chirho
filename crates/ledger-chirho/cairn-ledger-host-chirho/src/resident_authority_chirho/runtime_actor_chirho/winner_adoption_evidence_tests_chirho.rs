// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

#[test]
fn adoption_evidence_refuses_before_any_accepted_barrier_exists_chirho() {
    let handoff_runtime_chirho = ResidentGd7WinnerHandoffRuntimeChirho::default();
    assert_eq!(
        require_accepted_attempt_digest_chirho(&handoff_runtime_chirho).unwrap_err(),
        ResidentGd7WinnerAdoptionEvidenceRefusalChirho::AcceptedBarrierMissingChirho,
        "preparing or fetching evidence before AcceptedChirho must refuse by identity"
    );
}
