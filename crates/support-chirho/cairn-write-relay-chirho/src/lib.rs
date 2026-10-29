// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Transport-neutral request/response contract for the serve write-forwarding workflow.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/serve-write-forwarding-design-chirho.md`.
//! This crate authenticates bounded relay envelopes. It deliberately has no root, filesystem,
//! HTTP, elector, or writer-authority dependency, and none of its verified wrappers grant mutation
//! authority.

mod port_chirho;
mod protocol_chirho;
mod refusal_chirho;

pub use port_chirho::{
    RelayDestinationExecutionFutureChirho, RelayDestinationExecutionPortChirho,
    RelayDestinationResponseChirho, RelayTransportFailureChirho,
    ServedLocalReadAuthorityPortChirho, ServedLocalReadAuthorityWitnessChirho,
    ServedWriteDispatchFutureChirho, ServedWriteDispatchInputChirho,
    ServedWriteDispatchOutcomeChirho, ServedWriteDispatchPortChirho, ServedWriteRelayFailureChirho,
    ServedWriteRelayFutureChirho, ServedWriteRelayPortChirho,
};
pub use protocol_chirho::{
    decode_and_authenticate_served_write_relay_request_chirho,
    decode_and_verify_served_write_relay_request_chirho,
    decode_and_verify_served_write_relay_response_chirho,
    relay_request_header_name_is_allowed_chirho, relay_response_header_name_is_allowed_chirho,
    relay_tenant_consistency_group_digest_chirho, AuthenticatedServedWriteRelayRequestChirho,
    CallerIdempotencyKeyChirho, CallerOperationBindingChirho,
    PreparedServedWriteRelayAttemptChirho, PreparedServedWriteRelayRequestV1Chirho,
    PreparedServedWriteRelayResponseV1Chirho, RelayEndToEndHeadersChirho,
    RelayIngressAdmissionChirho, RelayIngressScopeChirho, RelayOutcomeClassChirho,
    RelayRosterChirho, ServedWriteRelayRequestInputChirho, ServedWriteRelayRequestV1Chirho,
    ServedWriteRelayResponseInputChirho, ServedWriteRelayResponseV1Chirho,
    VerifiedServedWriteRelayRequestChirho, VerifiedServedWriteRelayResponseChirho,
    CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO, CALLER_IDEMPOTENCY_KEY_MAX_BYTES_CHIRHO,
    RELAY_BODY_MAX_BYTES_CHIRHO, RELAY_REQUEST_WIRE_MAX_BYTES_CHIRHO,
    RELAY_RESPONSE_BODY_MAX_BYTES_CHIRHO, RELAY_RESPONSE_WIRE_MAX_BYTES_CHIRHO,
    SERVED_WRITE_RELAY_REQUEST_SCHEMA_V1_CHIRHO, SERVED_WRITE_RELAY_RESPONSE_SCHEMA_V1_CHIRHO,
};
pub use refusal_chirho::{
    RelayContractErrorChirho, RelayExecutionKnowledgeChirho, RelayRefusalIdentityChirho,
};
