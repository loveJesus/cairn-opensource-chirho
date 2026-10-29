// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Bounded identities that may cross the verified-prefix HTTP refusal boundary.

const PREFIX_REFUSAL_IDENTITIES_CHIRHO: [&str; 6] = [
    "LedgerMirrorPrefixManifestAuthorityRefusedChirho",
    "LedgerMirrorPrefixPageCrossContinuityRefusedChirho",
    "LedgerMirrorPrefixSealContinuityRefusedChirho",
    "LedgerMirrorPrefixSealClosureRefusedChirho",
    "LedgerMirrorBootstrapHeadAuthorityRollbackRefusedChirho",
    "LedgerMirrorBootstrapHeadRollbackOrConflictRefusedChirho",
];

pub(crate) fn prefix_refusal_identity_in_detail_chirho(
    detail_chirho: &str,
) -> Option<&'static str> {
    PREFIX_REFUSAL_IDENTITIES_CHIRHO
        .into_iter()
        .find(|identity_chirho| detail_chirho.contains(identity_chirho))
}

pub(crate) fn exact_prefix_refusal_identity_chirho(candidate_chirho: &str) -> Option<&'static str> {
    PREFIX_REFUSAL_IDENTITIES_CHIRHO
        .into_iter()
        .find(|identity_chirho| candidate_chirho == *identity_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn bounded_prefix_refusals_preserve_known_identity_and_reject_detail_chirho() {
        let identity_chirho = "LedgerMirrorBootstrapHeadRollbackOrConflictRefusedChirho";
        assert_eq!(
            prefix_refusal_identity_in_detail_chirho(&format!(
                "holder seal failed: {identity_chirho}"
            )),
            Some(identity_chirho)
        );
        assert_eq!(
            exact_prefix_refusal_identity_chirho(identity_chirho),
            Some(identity_chirho)
        );
        assert_eq!(
            exact_prefix_refusal_identity_chirho(&format!("detail: {identity_chirho}")),
            None
        );
        assert_eq!(exact_prefix_refusal_identity_chirho("private path"), None);
    }
}
