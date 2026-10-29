// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::{
    CallerIdempotencyKeyChirho, PreparedServedWriteRelayAttemptChirho, RelayContractErrorChirho,
    RelayEndToEndHeadersChirho, RelayExecutionKnowledgeChirho, RelayIngressAdmissionChirho,
    RelayIngressScopeChirho, RelayOutcomeClassChirho, RelayRefusalIdentityChirho,
    VerifiedServedWriteRelayRequestChirho, VerifiedServedWriteRelayResponseChirho,
};
use std::fmt;
use std::future::Future;
use std::pin::Pin;

pub type ServedWriteRelayFutureChirho<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, ServedWriteRelayFailureChirho>> + Send + 'a>>;

/// Transport-neutral one-hop relay port.
///
/// The request bytes are already bounded and signed by the contract layer. Implementations return
/// the exact bounded response bytes or one of the three transport failure shapes whose execution
/// knowledge is fixed here. The port carries no authority or mutation callback.
pub trait ServedWriteRelayPortChirho: Send + Sync {
    fn relay_one_hop_chirho<'a>(
        &'a self,
        attempt_chirho: &'a PreparedServedWriteRelayAttemptChirho,
    ) -> ServedWriteRelayFutureChirho<'a>;
}

pub struct ServedWriteDispatchInputChirho {
    pub ingress_admission_chirho: Option<RelayIngressAdmissionChirho>,
    pub caller_idempotency_key_chirho: CallerIdempotencyKeyChirho,
    pub method_chirho: String,
    pub uri_chirho: String,
    pub end_to_end_headers_chirho: RelayEndToEndHeadersChirho,
    pub body_chirho: Vec<u8>,
}

pub enum ServedWriteDispatchOutcomeChirho {
    ExecuteLocallyChirho,
    RelayedChirho(Box<VerifiedServedWriteRelayResponseChirho>),
}

/// Opaque evidence that one elected-era read began on the current local owner.
///
/// The serving layer must return this value to the same authority port immediately before and
/// after DAG execution. Those checks catch a leader or term change before execution or payload
/// release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedLocalReadAuthorityWitnessChirho {
    local_node_id_chirho: String,
    term_chirho: u64,
}

impl ServedLocalReadAuthorityWitnessChirho {
    pub fn new_chirho(local_node_id_chirho: String, term_chirho: u64) -> Self {
        Self {
            local_node_id_chirho,
            term_chirho,
        }
    }

    pub fn local_node_id_chirho(&self) -> &str {
        &self.local_node_id_chirho
    }

    pub const fn term_chirho(&self) -> u64 {
        self.term_chirho
    }
}

/// Read-only local-owner admission for an elected-era served read.
///
/// This port never relays and carries no root or mutation callback. A caller begins before any
/// potentially recording selection, then confirms the same witness immediately before executing a
/// capability-bounded read and again before releasing the response bytes.
pub trait ServedLocalReadAuthorityPortChirho: Send + Sync {
    fn begin_local_read_chirho(
        &self,
    ) -> Result<ServedLocalReadAuthorityWitnessChirho, ServedWriteRelayFailureChirho>;

    fn confirm_local_read_chirho(
        &self,
        witness_chirho: &ServedLocalReadAuthorityWitnessChirho,
    ) -> Result<(), ServedWriteRelayFailureChirho>;
}

pub type ServedWriteDispatchFutureChirho<'a> = Pin<
    Box<
        dyn Future<Output = Result<ServedWriteDispatchOutcomeChirho, ServedWriteRelayFailureChirho>>
            + Send
            + 'a,
    >,
>;

/// Decide whether an elected-era served request executes on this process or one remote owner.
///
/// The implementation may resolve election state, sign a relay envelope, and use one transport.
/// It receives no root mutation callback and returns no writer authority.
pub trait ServedWriteDispatchPortChirho: Send + Sync {
    fn ingress_scope_chirho(&self) -> Option<RelayIngressScopeChirho> {
        None
    }

    fn dispatch_chirho<'a>(
        &'a self,
        input_chirho: ServedWriteDispatchInputChirho,
    ) -> ServedWriteDispatchFutureChirho<'a>;
}

pub type RelayDestinationExecutionFutureChirho<'a> =
    Pin<Box<dyn Future<Output = RelayDestinationResponseChirho> + Send + 'a>>;

/// Process-local destination re-entry for one already authenticated relay request.
///
/// This port carries the request semantics but no root handle, filesystem capability, or writer
/// authority. Its implementation must re-enter the served request path so the destination's own
/// authority door decides whether any mutation can occur.
pub trait RelayDestinationExecutionPortChirho: Send + Sync {
    fn execute_verified_chirho<'a>(
        &'a self,
        request_chirho: &'a VerifiedServedWriteRelayRequestChirho,
    ) -> RelayDestinationExecutionFutureChirho<'a>;
}

pub struct RelayDestinationResponseChirho {
    outcome_class_chirho: RelayOutcomeClassChirho,
    outcome_identity_chirho: Option<String>,
    status_chirho: u16,
    headers_chirho: RelayEndToEndHeadersChirho,
    body_chirho: Vec<u8>,
}

impl RelayDestinationResponseChirho {
    pub fn served_chirho(
        status_chirho: u16,
        headers_chirho: RelayEndToEndHeadersChirho,
        body_chirho: Vec<u8>,
    ) -> Self {
        Self {
            outcome_class_chirho: RelayOutcomeClassChirho::ServedResponseChirho,
            outcome_identity_chirho: None,
            status_chirho,
            headers_chirho,
            body_chirho,
        }
    }

    pub fn door_refusal_chirho(
        identity_chirho: impl Into<String>,
        status_chirho: u16,
        headers_chirho: RelayEndToEndHeadersChirho,
        body_chirho: Vec<u8>,
    ) -> Self {
        Self {
            outcome_class_chirho: RelayOutcomeClassChirho::DoorRefusalChirho,
            outcome_identity_chirho: Some(identity_chirho.into()),
            status_chirho,
            headers_chirho,
            body_chirho,
        }
    }

    pub fn relay_refusal_chirho(identity_chirho: RelayRefusalIdentityChirho) -> Self {
        Self {
            outcome_class_chirho: RelayOutcomeClassChirho::RelayRefusalChirho,
            outcome_identity_chirho: Some(identity_chirho.as_str_chirho().to_string()),
            status_chirho: 409,
            headers_chirho: RelayEndToEndHeadersChirho::try_response_chirho(Vec::new())
                .expect("an empty response-header allowlist is valid"),
            body_chirho: Vec::new(),
        }
    }

    pub fn into_parts_chirho(
        self,
    ) -> (
        RelayOutcomeClassChirho,
        Option<String>,
        u16,
        RelayEndToEndHeadersChirho,
        Vec<u8>,
    ) {
        (
            self.outcome_class_chirho,
            self.outcome_identity_chirho,
            self.status_chirho,
            self.headers_chirho,
            self.body_chirho,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServedWriteRelayFailureChirho {
    ContractChirho(RelayContractErrorChirho),
    TransportChirho(RelayTransportFailureChirho),
}

impl ServedWriteRelayFailureChirho {
    pub const fn identity_chirho(&self) -> RelayRefusalIdentityChirho {
        match self {
            Self::ContractChirho(error_chirho) => error_chirho.identity_chirho(),
            Self::TransportChirho(error_chirho) => error_chirho.identity_chirho(),
        }
    }

    pub const fn execution_knowledge_chirho(&self) -> RelayExecutionKnowledgeChirho {
        match self {
            Self::ContractChirho(error_chirho) => error_chirho.execution_knowledge_chirho(),
            Self::TransportChirho(error_chirho) => error_chirho.execution_knowledge_chirho(),
        }
    }
}

impl From<RelayContractErrorChirho> for ServedWriteRelayFailureChirho {
    fn from(error_chirho: RelayContractErrorChirho) -> Self {
        Self::ContractChirho(error_chirho)
    }
}

impl From<RelayTransportFailureChirho> for ServedWriteRelayFailureChirho {
    fn from(error_chirho: RelayTransportFailureChirho) -> Self {
        Self::TransportChirho(error_chirho)
    }
}

impl fmt::Display for ServedWriteRelayFailureChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContractChirho(error_chirho) => error_chirho.fmt(formatter_chirho),
            Self::TransportChirho(error_chirho) => error_chirho.fmt(formatter_chirho),
        }
    }
}

impl std::error::Error for ServedWriteRelayFailureChirho {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayTransportFailureChirho {
    identity_chirho: RelayRefusalIdentityChirho,
    execution_knowledge_chirho: RelayExecutionKnowledgeChirho,
}

impl RelayTransportFailureChirho {
    pub const fn owner_unavailable_before_send_chirho() -> Self {
        Self {
            identity_chirho: RelayRefusalIdentityChirho::RelayOwnerUnavailableChirho,
            execution_knowledge_chirho: RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        }
    }

    pub const fn outcome_ambiguous_after_transmission_chirho() -> Self {
        Self {
            identity_chirho: RelayRefusalIdentityChirho::RelayOutcomeAmbiguousChirho,
            execution_knowledge_chirho: RelayExecutionKnowledgeChirho::MayHaveExecutedChirho,
        }
    }

    pub const fn response_unavailable_after_execution_chirho() -> Self {
        Self {
            identity_chirho:
                RelayRefusalIdentityChirho::RelayResponseUnavailableAfterExecutionChirho,
            execution_knowledge_chirho: RelayExecutionKnowledgeChirho::MayHaveExecutedChirho,
        }
    }

    pub const fn identity_chirho(self) -> RelayRefusalIdentityChirho {
        self.identity_chirho
    }

    pub const fn execution_knowledge_chirho(self) -> RelayExecutionKnowledgeChirho {
        self.execution_knowledge_chirho
    }
}

impl fmt::Display for RelayTransportFailureChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(self.identity_chirho.as_str_chirho())
    }
}

impl std::error::Error for RelayTransportFailureChirho {}

#[cfg(test)]
#[path = "port_chirho/tests_chirho.rs"]
mod tests_chirho;
