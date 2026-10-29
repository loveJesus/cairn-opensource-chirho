// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayExecutionKnowledgeChirho {
    DefinitelyNotExecutedChirho,
    MayHaveExecutedChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayRefusalIdentityChirho {
    RelayWireTooLargeChirho,
    RelayWireDecodeRefusedChirho,
    RelaySchemaUnsupportedChirho,
    RelayOriginNodeInvalidChirho,
    RelayOriginUnrosteredChirho,
    RelayRecipientMismatchChirho,
    RelayConsistencyGroupMismatchChirho,
    RelayTermInvalidChirho,
    RelayHopInvalidChirho,
    RelayCallerKeyInvalidChirho,
    RelayCallerKeyCollisionChirho,
    RelayMethodInvalidChirho,
    RelayUriInvalidChirho,
    RelayHeaderInvalidChirho,
    RelayBodyTooLargeChirho,
    RelayBodyDigestMismatchChirho,
    RelayBudgetInvalidChirho,
    RelayIngressAdmissionInvalidChirho,
    RelayRequestDigestMismatchChirho,
    RelayRequestSignatureInvalidChirho,
    RelayResponseStatusInvalidChirho,
    RelayResponseOutcomeInvalidChirho,
    RelayResponseDigestMismatchChirho,
    RelayResponseAuthenticationRefusedChirho,
    RelayOwnerUnknownChirho,
    RelayOwnerUnroutableChirho,
    RelayLeaseExpiredChirho,
    RelayOwnerUnavailableChirho,
    RelayOutcomeAmbiguousChirho,
    RelayOwnerTermChangedChirho,
    RelayResponseUnavailableAfterExecutionChirho,
    RelayLocalAuthorityUnavailableChirho,
    RelayMutationFamilyUnconvertedChirho,
    RelayPlatformRootIdentityUnavailableChirho,
}

impl RelayRefusalIdentityChirho {
    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::RelayWireTooLargeChirho => "RelayWireTooLargeChirho",
            Self::RelayWireDecodeRefusedChirho => "RelayWireDecodeRefusedChirho",
            Self::RelaySchemaUnsupportedChirho => "RelaySchemaUnsupportedChirho",
            Self::RelayOriginNodeInvalidChirho => "RelayOriginNodeInvalidChirho",
            Self::RelayOriginUnrosteredChirho => "RelayOriginUnrosteredChirho",
            Self::RelayRecipientMismatchChirho => "RelayRecipientMismatchChirho",
            Self::RelayConsistencyGroupMismatchChirho => "RelayConsistencyGroupMismatchChirho",
            Self::RelayTermInvalidChirho => "RelayTermInvalidChirho",
            Self::RelayHopInvalidChirho => "RelayHopInvalidChirho",
            Self::RelayCallerKeyInvalidChirho => "RelayCallerKeyInvalidChirho",
            Self::RelayCallerKeyCollisionChirho => "RelayCallerKeyCollisionChirho",
            Self::RelayMethodInvalidChirho => "RelayMethodInvalidChirho",
            Self::RelayUriInvalidChirho => "RelayUriInvalidChirho",
            Self::RelayHeaderInvalidChirho => "RelayHeaderInvalidChirho",
            Self::RelayBodyTooLargeChirho => "RelayBodyTooLargeChirho",
            Self::RelayBodyDigestMismatchChirho => "RelayBodyDigestMismatchChirho",
            Self::RelayBudgetInvalidChirho => "RelayBudgetInvalidChirho",
            Self::RelayIngressAdmissionInvalidChirho => "RelayIngressAdmissionInvalidChirho",
            Self::RelayRequestDigestMismatchChirho => "RelayRequestDigestMismatchChirho",
            Self::RelayRequestSignatureInvalidChirho => "RelayRequestSignatureInvalidChirho",
            Self::RelayResponseStatusInvalidChirho => "RelayResponseStatusInvalidChirho",
            Self::RelayResponseOutcomeInvalidChirho => "RelayResponseOutcomeInvalidChirho",
            Self::RelayResponseDigestMismatchChirho => "RelayResponseDigestMismatchChirho",
            Self::RelayResponseAuthenticationRefusedChirho => {
                "RelayResponseAuthenticationRefusedChirho"
            }
            Self::RelayOwnerUnknownChirho => "RelayOwnerUnknownChirho",
            Self::RelayOwnerUnroutableChirho => "RelayOwnerUnroutableChirho",
            Self::RelayLeaseExpiredChirho => "RelayLeaseExpiredChirho",
            Self::RelayOwnerUnavailableChirho => "RelayOwnerUnavailableChirho",
            Self::RelayOutcomeAmbiguousChirho => "RelayOutcomeAmbiguousChirho",
            Self::RelayOwnerTermChangedChirho => "RelayOwnerTermChangedChirho",
            Self::RelayResponseUnavailableAfterExecutionChirho => {
                "RelayResponseUnavailableAfterExecutionChirho"
            }
            Self::RelayLocalAuthorityUnavailableChirho => "RelayLocalAuthorityUnavailableChirho",
            Self::RelayMutationFamilyUnconvertedChirho => "RelayMutationFamilyUnconvertedChirho",
            Self::RelayPlatformRootIdentityUnavailableChirho => {
                "RelayPlatformRootIdentityUnavailableChirho"
            }
        }
    }

    pub fn from_str_chirho(value_chirho: &str) -> Option<Self> {
        [
            Self::RelayWireTooLargeChirho,
            Self::RelayWireDecodeRefusedChirho,
            Self::RelaySchemaUnsupportedChirho,
            Self::RelayOriginNodeInvalidChirho,
            Self::RelayOriginUnrosteredChirho,
            Self::RelayRecipientMismatchChirho,
            Self::RelayConsistencyGroupMismatchChirho,
            Self::RelayTermInvalidChirho,
            Self::RelayHopInvalidChirho,
            Self::RelayCallerKeyInvalidChirho,
            Self::RelayCallerKeyCollisionChirho,
            Self::RelayMethodInvalidChirho,
            Self::RelayUriInvalidChirho,
            Self::RelayHeaderInvalidChirho,
            Self::RelayBodyTooLargeChirho,
            Self::RelayBodyDigestMismatchChirho,
            Self::RelayBudgetInvalidChirho,
            Self::RelayIngressAdmissionInvalidChirho,
            Self::RelayRequestDigestMismatchChirho,
            Self::RelayRequestSignatureInvalidChirho,
            Self::RelayResponseStatusInvalidChirho,
            Self::RelayResponseOutcomeInvalidChirho,
            Self::RelayResponseDigestMismatchChirho,
            Self::RelayResponseAuthenticationRefusedChirho,
            Self::RelayOwnerUnknownChirho,
            Self::RelayOwnerUnroutableChirho,
            Self::RelayLeaseExpiredChirho,
            Self::RelayOwnerUnavailableChirho,
            Self::RelayOutcomeAmbiguousChirho,
            Self::RelayOwnerTermChangedChirho,
            Self::RelayResponseUnavailableAfterExecutionChirho,
            Self::RelayLocalAuthorityUnavailableChirho,
            Self::RelayMutationFamilyUnconvertedChirho,
            Self::RelayPlatformRootIdentityUnavailableChirho,
        ]
        .into_iter()
        .find(|identity_chirho| identity_chirho.as_str_chirho() == value_chirho)
    }

    /// Interpret a signed destination outcome conservatively.
    ///
    /// The listed identities are produced before the destination enters the served mutation path.
    /// Every other signed relay refusal is treated as possibly executed, so a newly introduced
    /// response-side identity cannot silently inherit the unsafe definite-failure default.
    pub const fn signed_outcome_execution_knowledge_chirho(self) -> RelayExecutionKnowledgeChirho {
        match self {
            Self::RelaySchemaUnsupportedChirho
            | Self::RelayOriginNodeInvalidChirho
            | Self::RelayOriginUnrosteredChirho
            | Self::RelayRecipientMismatchChirho
            | Self::RelayConsistencyGroupMismatchChirho
            | Self::RelayTermInvalidChirho
            | Self::RelayHopInvalidChirho
            | Self::RelayCallerKeyInvalidChirho
            | Self::RelayCallerKeyCollisionChirho
            | Self::RelayMethodInvalidChirho
            | Self::RelayUriInvalidChirho
            | Self::RelayHeaderInvalidChirho
            | Self::RelayBodyTooLargeChirho
            | Self::RelayBodyDigestMismatchChirho
            | Self::RelayBudgetInvalidChirho
            | Self::RelayIngressAdmissionInvalidChirho
            | Self::RelayRequestDigestMismatchChirho
            | Self::RelayRequestSignatureInvalidChirho
            | Self::RelayOwnerUnknownChirho
            | Self::RelayOwnerUnroutableChirho
            | Self::RelayLeaseExpiredChirho
            | Self::RelayOwnerUnavailableChirho
            | Self::RelayOwnerTermChangedChirho
            | Self::RelayLocalAuthorityUnavailableChirho
            | Self::RelayMutationFamilyUnconvertedChirho
            | Self::RelayPlatformRootIdentityUnavailableChirho => {
                RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho
            }
            _ => RelayExecutionKnowledgeChirho::MayHaveExecutedChirho,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayContractErrorChirho {
    identity_chirho: RelayRefusalIdentityChirho,
    detail_chirho: &'static str,
    execution_knowledge_chirho: RelayExecutionKnowledgeChirho,
}

impl RelayContractErrorChirho {
    pub const fn ingress_admission_invalid_chirho() -> Self {
        Self::new_chirho(
            RelayRefusalIdentityChirho::RelayIngressAdmissionInvalidChirho,
            "relay ingress policy or trusted origin scope is absent or incompatible",
        )
    }

    pub(crate) const fn new_chirho(
        identity_chirho: RelayRefusalIdentityChirho,
        detail_chirho: &'static str,
    ) -> Self {
        Self {
            identity_chirho,
            detail_chirho,
            execution_knowledge_chirho: RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        }
    }

    pub(crate) const fn after_request_may_have_executed_chirho(mut self) -> Self {
        self.execution_knowledge_chirho = RelayExecutionKnowledgeChirho::MayHaveExecutedChirho;
        self
    }

    pub const fn owner_unknown_chirho() -> Self {
        Self::new_chirho(
            RelayRefusalIdentityChirho::RelayOwnerUnknownChirho,
            "local election view has no current relay owner",
        )
    }

    pub const fn owner_unroutable_chirho() -> Self {
        Self::new_chirho(
            RelayRefusalIdentityChirho::RelayOwnerUnroutableChirho,
            "current relay owner has no reviewed private-mesh endpoint",
        )
    }

    pub const fn lease_expired_chirho() -> Self {
        Self::new_chirho(
            RelayRefusalIdentityChirho::RelayLeaseExpiredChirho,
            "relay lease duration is absent, exhausted, or expired",
        )
    }

    pub const fn owner_term_changed_chirho() -> Self {
        Self::new_chirho(
            RelayRefusalIdentityChirho::RelayOwnerTermChangedChirho,
            "relay owner or term changed before destination execution",
        )
    }

    pub const fn request_signing_refused_chirho() -> Self {
        Self::new_chirho(
            RelayRefusalIdentityChirho::RelayRequestSignatureInvalidChirho,
            "origin could not sign the bounded relay request with its configured node key",
        )
    }

    pub const fn local_authority_unavailable_chirho() -> Self {
        Self::new_chirho(
            RelayRefusalIdentityChirho::RelayLocalAuthorityUnavailableChirho,
            "local elected owner has no composed resident mutation authority",
        )
    }

    pub const fn identity_chirho(&self) -> RelayRefusalIdentityChirho {
        self.identity_chirho
    }

    pub const fn execution_knowledge_chirho(&self) -> RelayExecutionKnowledgeChirho {
        self.execution_knowledge_chirho
    }
}

impl fmt::Display for RelayContractErrorChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter_chirho,
            "{}: {}",
            self.identity_chirho.as_str_chirho(),
            self.detail_chirho
        )
    }
}

impl std::error::Error for RelayContractErrorChirho {}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn directory_refusal_factories_remain_named_and_pre_execution_chirho() {
        for (error_chirho, expected_chirho) in [
            (
                RelayContractErrorChirho::owner_unknown_chirho(),
                RelayRefusalIdentityChirho::RelayOwnerUnknownChirho,
            ),
            (
                RelayContractErrorChirho::owner_unroutable_chirho(),
                RelayRefusalIdentityChirho::RelayOwnerUnroutableChirho,
            ),
            (
                RelayContractErrorChirho::lease_expired_chirho(),
                RelayRefusalIdentityChirho::RelayLeaseExpiredChirho,
            ),
            (
                RelayContractErrorChirho::owner_term_changed_chirho(),
                RelayRefusalIdentityChirho::RelayOwnerTermChangedChirho,
            ),
            (
                RelayContractErrorChirho::request_signing_refused_chirho(),
                RelayRefusalIdentityChirho::RelayRequestSignatureInvalidChirho,
            ),
            (
                RelayContractErrorChirho::local_authority_unavailable_chirho(),
                RelayRefusalIdentityChirho::RelayLocalAuthorityUnavailableChirho,
            ),
        ] {
            assert_eq!(error_chirho.identity_chirho(), expected_chirho);
            assert_eq!(
                error_chirho.execution_knowledge_chirho(),
                RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho
            );
        }
    }
}
