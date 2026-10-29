// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the move-stage envelope.
//!
//! Two carry weight beyond hygiene. [`a_self_reported_digest_is_not_trusted_chirho`] is the attack the
//! envelope exists for: a record carries its own digest AND a signature over it, so a verifier that
//! believed the declared digest would be checking a signature over a number the record chose — and the
//! intent underneath could claim any stage, including retirement. And
//! [`a_record_from_another_move_is_refused_chirho`] stops a stage record being replayed sideways into a
//! different move, which is how a move could be advanced by evidence that was never about it.

use super::*;
use crate::move_chirho::move_stages_chirho::MoveStageChirho;

const KEY_CHIRHO: &str = "move-authority-key-chirho";
const MOVE_CHIRHO: &str = "move-a-chirho";

struct AuthorityChirho;

impl MoveAuthorityPortChirho for AuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, msg_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{msg_chirho}")
    }
}

fn signed_at_chirho(
    stage_chirho: MoveStageChirho,
    target_chirho: &str,
    stage_seq_chirho: u64,
) -> MoveStageAttestationChirho {
    // Only the surfaces-carrying stage may name evidence, so the helper mirrors that rule rather than
    // attaching a digest everywhere and hiding the binding it is supposed to exercise.
    let evidence_chirho = match stage_chirho {
        MoveStageChirho::SurfacesCarriedChirho => Some("e".repeat(64)),
        _ => None,
    };
    let post_handoff_record_digests_chirho = match stage_chirho {
        MoveStageChirho::WriterHandedOffChirho => {
            vec![move_stage_record_digest_chirho(&signed_at_chirho(
                MoveStageChirho::SourceRetiredChirho,
                target_chirho,
                stage_seq_chirho + 1,
            ))
            .expect("terminal record digest")]
        }
        _ => Vec::new(),
    };
    let intent_chirho = MoveStageIntentChirho {
        schema_chirho: MOVE_STAGE_INTENT_SCHEMA_V2_CHIRHO.to_string(),
        move_id_chirho: MOVE_CHIRHO.to_string(),
        source_root_chirho: "root-source-chirho".to_string(),
        target_root_chirho: target_chirho.to_string(),
        stage_chirho,
        surfaces_evidence_chirho: evidence_chirho,
        post_handoff_record_digests_chirho,
        retirement_authorization_digest_chirho: match stage_chirho {
            MoveStageChirho::SourceRetiredChirho => Some("a".repeat(64)),
            _ => None,
        },
        stage_seq_chirho,
    };
    let mut record_chirho = MoveStageAttestationChirho {
        schema_chirho: MOVE_STAGE_ATTESTATION_SCHEMA_V2_CHIRHO.to_string(),
        signature_domain_chirho: MOVE_STAGE_ATTESTATION_DOMAIN_V2_CHIRHO.to_string(),
        intent_digest_chirho: move_stage_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_move_stage_message_chirho(&record_chirho)
    );
    record_chirho
}

fn signed_chirho(stage_chirho: MoveStageChirho, target_chirho: &str) -> MoveStageAttestationChirho {
    signed_at_chirho(stage_chirho, target_chirho, 1)
}

fn prepared_chirho() -> MoveStageAttestationChirho {
    signed_chirho(MoveStageChirho::PreparedChirho, "root-target-chirho")
}

fn resign_chirho(record_chirho: &mut MoveStageAttestationChirho) {
    record_chirho.intent_digest_chirho =
        move_stage_intent_digest_chirho(&record_chirho.intent_chirho).expect("digest");
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_move_stage_message_chirho(record_chirho)
    );
}

#[test]
fn a_correctly_signed_stage_verifies_chirho() {
    // Positive control: every refusal below would pass against a verifier that refused everything.
    let verified_chirho =
        verify_move_stage_chirho(&prepared_chirho(), &AuthorityChirho, MOVE_CHIRHO)
            .expect("verifies");
    assert_eq!(verified_chirho.move_id_chirho(), MOVE_CHIRHO);
    assert_eq!(
        verified_chirho.stage_chirho(),
        MoveStageChirho::PreparedChirho
    );
    assert_eq!(verified_chirho.source_root_chirho(), "root-source-chirho");
}

#[test]
fn a_self_reported_digest_is_not_trusted_chirho() {
    // THE attack. Believing the declared digest means checking a signature over a number the record
    // chose, while the intent underneath claims whatever its author wanted — here, jumping straight to
    // retirement, which erases a source key.
    let mut forged_chirho = prepared_chirho();
    forged_chirho.intent_chirho.stage_chirho = MoveStageChirho::SourceRetiredChirho;
    assert!(
        matches!(
            verify_move_stage_chirho(&forged_chirho, &AuthorityChirho, MOVE_CHIRHO)
                .expect_err("must refuse"),
            MoveStageRefusalChirho::IntentDigestMismatchChirho { .. }
        ),
        "must refuse on the RECOMPUTED digest rather than on the signature"
    );
}

#[test]
fn a_record_from_another_move_is_refused_chirho() {
    // A perfectly valid record, signed by the right authority, for a DIFFERENT move. Without this
    // binding, one move's evidence advances another.
    assert!(matches!(
        verify_move_stage_chirho(&prepared_chirho(), &AuthorityChirho, "move-b-chirho")
            .expect_err("wrong move"),
        MoveStageRefusalChirho::MoveMismatchChirho { .. }
    ));
}

#[test]
fn a_move_whose_source_is_its_target_is_refused_chirho() {
    // It moves nothing, and its retirement stage would erase the key of the root it just handed to
    // itself — a self-inflicted unsignable root out of a record that otherwise verifies.
    assert_eq!(
        verify_move_stage_chirho(
            &signed_chirho(MoveStageChirho::PreparedChirho, "root-source-chirho"),
            &AuthorityChirho,
            MOVE_CHIRHO
        )
        .expect_err("source is target"),
        MoveStageRefusalChirho::SourceIsTargetChirho
    );
}

#[test]
fn an_unknown_key_refuses_as_an_unknown_key_not_a_bad_signature_chirho() {
    let mut record_chirho = prepared_chirho();
    record_chirho.authority_key_id_chirho = "someone-elses-key-chirho".to_string();
    assert!(matches!(
        verify_move_stage_chirho(&record_chirho, &AuthorityChirho, MOVE_CHIRHO)
            .expect_err("unknown"),
        MoveStageRefusalChirho::UnknownAuthorityKeyChirho { .. }
    ));
}

#[test]
fn a_bad_signature_refuses_chirho() {
    let mut record_chirho = prepared_chirho();
    record_chirho.sig_chirho = "sig-over:something-else-chirho".to_string();
    assert_eq!(
        verify_move_stage_chirho(&record_chirho, &AuthorityChirho, MOVE_CHIRHO)
            .expect_err("bad sig"),
        MoveStageRefusalChirho::BadSignatureChirho
    );
}

#[test]
fn a_signature_bound_sized_for_a_token_would_refuse_every_real_signature_chirho() {
    // Positive control on the BOUNDS. A bare ed25519 hex signature is exactly 128 characters, so one
    // shared 128-byte limit would refuse every correct record — a mistake the negative arms above could
    // never reveal, and one this repo has already paid for once.
    let mut record_chirho = prepared_chirho();
    record_chirho.sig_chirho = "a".repeat(128);
    assert!(!matches!(
        verify_move_stage_chirho(&record_chirho, &AuthorityChirho, MOVE_CHIRHO),
        Err(MoveStageRefusalChirho::FieldTooLongChirho { .. })
    ));
}

#[test]
fn surfaces_carried_without_evidence_is_refused_chirho() {
    // The stage that claims a tenant's complete signed history, projections and audit coordinates
    // arrived at the target. Signing that without naming the verification behind it is an assertion
    // wearing a signature -- the clause asks for those things PRESERVED, not asserted.
    let mut record_chirho =
        signed_chirho(MoveStageChirho::SurfacesCarriedChirho, "root-target-chirho");
    record_chirho.intent_chirho.surfaces_evidence_chirho = None;
    resign_chirho(&mut record_chirho);
    assert_eq!(
        verify_move_stage_chirho(&record_chirho, &AuthorityChirho, MOVE_CHIRHO)
            .expect_err("no evidence"),
        MoveStageRefusalChirho::SurfacesCarriedWithoutEvidenceChirho
    );
}

#[test]
fn evidence_on_a_stage_that_carries_nothing_is_refused_rather_than_ignored_chirho() {
    // Ignoring it would be worse than refusing: a digest nobody checks reads as though something was
    // verified, and it would sit in an append-only log saying so forever.
    let mut record_chirho =
        signed_chirho(MoveStageChirho::WriterHandedOffChirho, "root-target-chirho");
    record_chirho.intent_chirho.surfaces_evidence_chirho = Some("e".repeat(64));
    resign_chirho(&mut record_chirho);
    assert_eq!(
        verify_move_stage_chirho(&record_chirho, &AuthorityChirho, MOVE_CHIRHO)
            .expect_err("evidence where none belongs"),
        MoveStageRefusalChirho::EvidenceOnANonCarryingStageChirho {
            stage_chirho: MoveStageChirho::WriterHandedOffChirho,
        }
    );
}

#[test]
fn surfaces_evidence_must_be_a_canonical_lowercase_blake3_digest_chirho() {
    for (label_chirho, evidence_chirho) in [
        ("empty", String::new()),
        ("short", "e".repeat(63)),
        ("long", "e".repeat(65)),
        ("uppercase", "E".repeat(64)),
        ("non-hex", format!("{}g", "e".repeat(63))),
    ] {
        let mut record_chirho =
            signed_chirho(MoveStageChirho::SurfacesCarriedChirho, "root-target-chirho");
        record_chirho.intent_chirho.surfaces_evidence_chirho = Some(evidence_chirho);
        resign_chirho(&mut record_chirho);
        assert_eq!(
            verify_move_stage_chirho(&record_chirho, &AuthorityChirho, MOVE_CHIRHO)
                .expect_err(label_chirho),
            MoveStageRefusalChirho::SurfacesEvidenceDigestNotCanonicalChirho,
            "{label_chirho} evidence must not satisfy a content-address claim"
        );
    }
}

#[test]
fn a_surfaces_carried_stage_with_evidence_verifies_chirho() {
    // Positive control for the pair above: without it, both would pass against a verifier that refused
    // every surfaces-carried record whatever it named.
    assert!(verify_move_stage_chirho(
        &signed_chirho(MoveStageChirho::SurfacesCarriedChirho, "root-target-chirho"),
        &AuthorityChirho,
        MOVE_CHIRHO
    )
    .is_ok());
}

#[test]
fn handoff_freezes_exactly_one_complete_terminal_record_chirho() {
    let handoff_chirho = signed_at_chirho(
        MoveStageChirho::WriterHandedOffChirho,
        "root-target-chirho",
        4,
    );
    let terminal_chirho = signed_at_chirho(
        MoveStageChirho::SourceRetiredChirho,
        "root-target-chirho",
        5,
    );
    assert_eq!(
        handoff_chirho
            .intent_chirho
            .post_handoff_record_digests_chirho,
        vec![move_stage_record_digest_chirho(&terminal_chirho).expect("terminal digest")]
    );
    assert!(verify_move_stage_chirho(&handoff_chirho, &AuthorityChirho, MOVE_CHIRHO).is_ok());

    for (count_chirho, digests_chirho) in
        [(0, Vec::new()), (2, vec!["b".repeat(64), "c".repeat(64)])]
    {
        let mut malformed_chirho = handoff_chirho.clone();
        malformed_chirho
            .intent_chirho
            .post_handoff_record_digests_chirho = digests_chirho;
        resign_chirho(&mut malformed_chirho);
        let error_chirho =
            verify_move_stage_chirho(&malformed_chirho, &AuthorityChirho, MOVE_CHIRHO)
                .expect_err("wrong terminal population refuses");
        if count_chirho == 0 {
            assert_eq!(
                error_chirho,
                MoveStageRefusalChirho::HandoffTerminalRecordCountChirho { found_chirho: 0 }
            );
        } else {
            assert_eq!(
                error_chirho,
                MoveStageRefusalChirho::PostHandoffRecordPopulationExceededChirho {
                    found_chirho: 2,
                    max_chirho: MOVE_POST_HANDOFF_RECORD_COUNT_CHIRHO,
                }
            );
        }
    }
}

#[test]
fn post_handoff_records_on_any_other_stage_refuse_chirho() {
    let mut prepared_chirho = prepared_chirho();
    prepared_chirho
        .intent_chirho
        .post_handoff_record_digests_chirho = vec!["b".repeat(64)];
    resign_chirho(&mut prepared_chirho);
    assert_eq!(
        verify_move_stage_chirho(&prepared_chirho, &AuthorityChirho, MOVE_CHIRHO)
            .expect_err("wrong stage"),
        MoveStageRefusalChirho::PostHandoffRecordsOnWrongStageChirho {
            stage_chirho: MoveStageChirho::PreparedChirho,
        }
    );
}

#[test]
fn retirement_requires_one_canonical_conditional_authorization_chirho() {
    let terminal_chirho = signed_at_chirho(
        MoveStageChirho::SourceRetiredChirho,
        "root-target-chirho",
        5,
    );
    assert!(verify_move_stage_chirho(&terminal_chirho, &AuthorityChirho, MOVE_CHIRHO).is_ok());

    let mut missing_chirho = terminal_chirho.clone();
    missing_chirho
        .intent_chirho
        .retirement_authorization_digest_chirho = None;
    resign_chirho(&mut missing_chirho);
    assert_eq!(
        verify_move_stage_chirho(&missing_chirho, &AuthorityChirho, MOVE_CHIRHO)
            .expect_err("missing authorization"),
        MoveStageRefusalChirho::RetirementAuthorizationMissingChirho
    );

    let mut malformed_chirho = terminal_chirho;
    malformed_chirho
        .intent_chirho
        .retirement_authorization_digest_chirho = Some("NOT-A-DIGEST-CHIRHO".to_string());
    resign_chirho(&mut malformed_chirho);
    assert_eq!(
        verify_move_stage_chirho(&malformed_chirho, &AuthorityChirho, MOVE_CHIRHO)
            .expect_err("malformed authorization"),
        MoveStageRefusalChirho::RetirementAuthorizationDigestNotCanonicalChirho
    );
}

#[test]
fn a_retirement_authorization_on_a_nonterminal_stage_refuses_chirho() {
    let mut prepared_chirho = prepared_chirho();
    prepared_chirho
        .intent_chirho
        .retirement_authorization_digest_chirho = Some("a".repeat(64));
    resign_chirho(&mut prepared_chirho);
    assert_eq!(
        verify_move_stage_chirho(&prepared_chirho, &AuthorityChirho, MOVE_CHIRHO)
            .expect_err("wrong stage"),
        MoveStageRefusalChirho::RetirementAuthorizationOnWrongStageChirho {
            stage_chirho: MoveStageChirho::PreparedChirho,
        }
    );
}

#[test]
fn complete_record_identity_includes_the_signature_chirho() {
    let record_chirho = prepared_chirho();
    let mut differently_signed_chirho = record_chirho.clone();
    differently_signed_chirho
        .sig_chirho
        .push_str("-different-chirho");
    assert_eq!(
        move_stage_intent_digest_chirho(&record_chirho.intent_chirho).expect("intent digest"),
        move_stage_intent_digest_chirho(&differently_signed_chirho.intent_chirho)
            .expect("same intent digest")
    );
    assert_ne!(
        move_stage_record_digest_chirho(&record_chirho).expect("record digest"),
        move_stage_record_digest_chirho(&differently_signed_chirho)
            .expect("different record digest"),
        "a permit must bind the full signed record, not merely its intent"
    );
}

#[test]
fn verified_control_records_expose_the_exact_verified_record_address_chirho() {
    let record_chirho = prepared_chirho();
    let verified_chirho =
        verify_move_control_record_chirho(&record_chirho, &AuthorityChirho, MOVE_CHIRHO)
            .expect("verified control record");
    assert_eq!(verified_chirho.record_chirho(), &record_chirho);
    assert_eq!(
        verified_chirho.verified_stage_chirho().stage_chirho(),
        MoveStageChirho::PreparedChirho
    );
    assert_eq!(
        verified_chirho.record_digest_chirho(),
        move_stage_record_digest_chirho(&record_chirho).expect("record digest")
    );
}
