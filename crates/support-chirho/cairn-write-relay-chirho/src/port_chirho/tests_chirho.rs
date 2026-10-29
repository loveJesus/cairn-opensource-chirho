// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

#[test]
fn transport_failures_cannot_erase_ambiguous_execution_chirho() {
    let pre_send_chirho = RelayTransportFailureChirho::owner_unavailable_before_send_chirho();
    assert_eq!(
        pre_send_chirho.execution_knowledge_chirho(),
        RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho
    );

    for ambiguous_chirho in [
        RelayTransportFailureChirho::outcome_ambiguous_after_transmission_chirho(),
        RelayTransportFailureChirho::response_unavailable_after_execution_chirho(),
    ] {
        assert_eq!(
            ambiguous_chirho.execution_knowledge_chirho(),
            RelayExecutionKnowledgeChirho::MayHaveExecutedChirho
        );
        assert_ne!(
            ambiguous_chirho.identity_chirho(),
            RelayRefusalIdentityChirho::RelayOwnerUnavailableChirho
        );
    }
}

#[test]
fn contract_and_transport_failures_preserve_their_exact_identity_chirho() {
    let transport_chirho = ServedWriteRelayFailureChirho::from(
        RelayTransportFailureChirho::outcome_ambiguous_after_transmission_chirho(),
    );
    assert_eq!(
        transport_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayOutcomeAmbiguousChirho
    );
    assert_eq!(
        transport_chirho.execution_knowledge_chirho(),
        RelayExecutionKnowledgeChirho::MayHaveExecutedChirho
    );
}
