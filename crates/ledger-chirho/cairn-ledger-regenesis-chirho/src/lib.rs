// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Operator-only CF6 ledger regenesis. This crate owns create authority; the serve runtime has no
//! dependency edge to it and therefore cannot compile against its provisioning surfaces.

mod bounded_file_chirho;
mod completion_chirho;
mod destination_authority_enrollment_chirho;
#[cfg(any(test, feature = "test-support-chirho"))]
#[path = "tests_chirho/destination_authority_enrollment_test_support_chirho.rs"]
pub mod destination_authority_enrollment_test_support_chirho;
mod error_chirho;
mod issuer_chirho;
mod ledger_host_artifact_derivation_chirho;
mod ledger_host_artifact_emission_chirho;
mod ledger_host_authoring_inputs_chirho;
mod ledger_host_authoring_load_chirho;
mod ledger_host_authoring_mode_chirho;
mod ledger_host_custody_binding_chirho;
mod localphaseb_support_chirho;
mod money_stage_chirho;
mod plan_chirho;
mod publication_verify_chirho;
mod shareable_evidence_chirho;
mod staging_chirho;

pub use completion_chirho::{
    canonical_ledger_regenesis_evidence_packet_chirho, complete_money_stage_chirho,
    ledger_regenesis_evidence_packet_digest_chirho,
    load_canonical_ledger_regenesis_evidence_packet_chirho,
    parse_canonical_ledger_regenesis_evidence_packet_chirho, run_ledger_regenesis_chirho,
    LedgerRegenesisCaveatChirho, LedgerRegenesisConservationEvidenceChirho,
    LedgerRegenesisEvidencePacketV2Chirho, LedgerRegenesisProjectionEvidenceChirho,
    LedgerRegenesisProjectionVerdictChirho, LedgerRegenesisSourcePrivacyEvidenceChirho,
    LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO,
    LEDGER_REGENESIS_EVIDENCE_PACKET_SCHEMA_V2_CHIRHO,
    MAX_LEDGER_REGENESIS_EVIDENCE_PACKET_BYTES_CHIRHO,
};
pub use destination_authority_enrollment_chirho::{
    author_destination_authority_enrollment_chirho, destination_authority_enrollment_digest_chirho,
    read_destination_authority_enrollment_chirho,
    read_digest_bound_destination_authority_enrollment_chirho,
    AuthoredDestinationAuthorityEnrollmentChirho,
    DestinationAuthorityEnrollmentAuthorRequestChirho,
    DestinationAuthorityEnrollmentIntentV1Chirho, DestinationAuthorityEnrollmentRecordV1Chirho,
    VerifiedDestinationAuthorityEnrollmentChirho,
    DESTINATION_AUTHORITY_ENROLLMENT_INTENT_SCHEMA_V1_CHIRHO,
    DESTINATION_AUTHORITY_ENROLLMENT_RECORD_SCHEMA_V1_CHIRHO,
    DESTINATION_AUTHORITY_ENROLLMENT_SIGNATURE_DOMAIN_V1_CHIRHO,
};
pub use error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
// `issuer_chirho` exports NOTHING. The two role-tagged pin derivations are deliberately not
// re-exported: since brick #3 they take the loaded runtime signers, and the only exported road that
// can produce those is the custody binding below. Brick #7 removed the two thin
// `offline_*_verifying_key_hex_chirho` helpers that used to be re-exported here — with the
// credits-demo author migrated onto the custody road they had zero callers, and they were the
// un-vouched pin road: a pin derived with no identity comparison at all.
pub use ledger_host_artifact_derivation_chirho::LedgerHostAuthoredArtifactsChirho;
// Brick #4's road AUTHORS and emits in one call rather than accepting an already-derived
// `LedgerHostCustodyBoundArtifactsChirho`: that type's fields are `pub`, so an outside caller could
// otherwise hand over artifacts carrying an invented issuer pin and have them written at mode 0600
// under a custody evidence value nothing proved. Emission therefore takes only untrusted inputs.
pub use ledger_host_artifact_emission_chirho::{
    author_and_emit_ledger_host_artifacts_chirho, ledger_host_config_digest_chirho,
    LedgerHostArtifactKindChirho, LedgerHostEmissionRequestChirho,
    LedgerHostEmittedArtifactsChirho,
};
pub use ledger_host_authoring_inputs_chirho::{
    canonical_ledger_host_authoring_inputs_bytes_chirho,
    ledger_host_authoring_inputs_digest_chirho,
    parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho,
    LedgerHostAuthoringInputsV1Chirho, LedgerHostAuthoringMemberInputChirho,
    LedgerHostAuthoringPostgresEffectInputChirho, LedgerHostAuthoringRouteInputChirho,
    LedgerHostAuthoringSignerRefsInputChirho, LEDGER_HOST_AUTHORING_INPUTS_SCHEMA_V1_CHIRHO,
};
// Brick #6's reviewed-document reader. BOTH exported names keep `money_policy_unchecked` in them
// because both return a document with zero money-policy validation; an operator surface that prints
// one without deriving first shows a reader something that looks validated and is not.
pub use ledger_host_authoring_load_chirho::{
    read_digest_bound_ledger_host_authoring_inputs_money_policy_unchecked_chirho,
    read_ledger_host_authoring_inputs_money_policy_unchecked_chirho,
    LoadedLedgerHostAuthoringInputsChirho,
};
// Brick #5's typed mode. Exported because every authoring road now REQUIRES it with no default, so
// an outside caller must be able to name the posture it is authoring. The coordinate enum travels
// with it because it is carried inside two refusals a caller must be able to match on.
pub use ledger_host_authoring_mode_chirho::{
    LedgerHostAuthoringModeChirho, LedgerHostAuthoringModeCoordinateChirho,
};
pub use ledger_host_custody_binding_chirho::{
    bind_custody_and_derive_ledger_host_artifacts_chirho, LedgerHostCustodyBoundArtifactsChirho,
    LedgerHostCustodyEvidenceChirho, LedgerHostCustodyRequestChirho,
};
pub use localphaseb_support_chirho::{
    verified_localphaseb_evidence_from_packet_chirho, LocalPhaseBPacketEvidenceChirho,
};
// Re-exported for packet-evidence consumers (the operator smoke) so their dep surface stays at
// this crate: the storage-path type the parent takes and the read-model census/evidence types the
// returned object exposes.
pub use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
pub use cairn_ledger_read_model_chirho::localphaseb_evidence_chirho::{
    EscrowOpKindChirho, EscrowRecordEvidenceChirho, LocalPhaseBOpCensusChirho,
    VerifiedLocalPhaseBEvidenceChirho,
};
pub use money_stage_chirho::{
    author_ledger_regenesis_activation_chirho, prepare_money_stage_chirho,
    LedgerRegenesisActivationArtifactChirho, LedgerRegenesisActivationAuthorRequestChirho,
    LedgerRegenesisActivationProofChirho, LedgerRegenesisCanaryProofChirho,
    LedgerRegenesisH3aRequestChirho, LedgerRegenesisMoneyProofChirho,
    LedgerRegenesisMoneyStageChirho,
};
pub use plan_chirho::{
    canonical_plan_bytes_chirho, plan_digest_chirho, LedgerRegenesisPlanV1Chirho,
    LedgerRegenesisProjectionRoutePlanChirho, LEDGER_REGENESIS_PLAN_SCHEMA_V1_CHIRHO,
};
pub use publication_verify_chirho::{
    canonical_ledger_regenesis_publication_manifest_chirho,
    ledger_regenesis_publication_manifest_digest_chirho,
    load_canonical_ledger_regenesis_publication_manifest_chirho,
    parse_canonical_ledger_regenesis_publication_manifest_chirho,
    LedgerRegenesisPublicationManifestV1Chirho, LedgerRegenesisPublicationProofChirho,
    LEDGER_REGENESIS_PUBLICATION_MANIFEST_FILE_CHIRHO,
    LEDGER_REGENESIS_PUBLICATION_MANIFEST_SCHEMA_V1_CHIRHO,
    MAX_LEDGER_REGENESIS_PUBLICATION_MANIFEST_BYTES_CHIRHO,
};
pub use shareable_evidence_chirho::{
    build_shareable_evidence_packet_chirho, canonical_shareable_evidence_packet_chirho,
    scan_forbidden_markers_chirho, shareable_manifest_node_chirho,
    verify_shareable_evidence_packet_chirho, ShareableEvidenceBarrierEventChirho,
    ShareableEvidenceFileClassChirho, ShareableEvidenceInputsChirho,
    ShareableEvidenceManifestNodeChirho, ShareableEvidencePacketChirho,
    ShareableEvidenceRefusalReasonChirho, ShareableEvidenceStatusChirho,
    ShareableEvidenceTermChirho, SHAREABLE_EVIDENCE_SCHEMA_V1_CHIRHO,
};
pub use staging_chirho::{
    publish_completed_stage_chirho, CompletedLedgerRegenesisStageChirho,
    PublishedLedgerRegenesisStageChirho,
};

#[cfg(test)]
#[path = "tests_chirho/mod_tests_chirho.rs"]
mod tests_chirho;
