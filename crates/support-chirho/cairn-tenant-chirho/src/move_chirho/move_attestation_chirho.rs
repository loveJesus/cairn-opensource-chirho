// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Each move stage as signed EVIDENCE, so "the move reached custody" is a claim somebody authorised.
//!
//! **Verify-only, no `sign_chirho`.** The party performing a move must not be able to author the
//! record that it went correctly — otherwise "custody is placed" is exactly as trustworthy as the
//! process that would benefit from saying so, and the whole ordering becomes advisory.
//!
//! **Both roots are named in the intent, and both are bound.** A stage record that named only the move
//! would let a target claim a stage in someone else's move; naming source and target and checking them
//! at verification means a record from another move cannot be replayed into this one.
//!
//! Same envelope contract as the other four: shape, bounds, KEY before signature, RECOMPUTED digest,
//! signature, then intent-specific bindings. The digest is recomputed rather than trusted, because a
//! record that carries its own digest and is believed has a signature over a number it chose.

use super::move_stages_chirho::MoveStageChirho;
use cairn_core_chirho::store_chirho::hash_object_chirho;
use serde::{Deserialize, Serialize};

pub const MOVE_STAGE_INTENT_SCHEMA_V2_CHIRHO: &str = "cairn.tenant-move-stage-intent.v2.chirho";
pub const MOVE_STAGE_ATTESTATION_SCHEMA_V2_CHIRHO: &str =
    "cairn.tenant-move-stage-attestation.v2.chirho";
pub const MOVE_STAGE_ATTESTATION_DOMAIN_V2_CHIRHO: &str =
    "cairn.tenant-move-stage-attestation.v2.signature.chirho";

pub const MAX_MOVE_TOKEN_BYTES_CHIRHO: usize = 128;
pub const MOVE_SURFACES_EVIDENCE_DIGEST_HEX_BYTES_CHIRHO: usize = 64;
pub const MOVE_POST_HANDOFF_RECORD_COUNT_CHIRHO: usize = 1;
/// A bare ed25519 hex signature is exactly 128 characters, so a shared 128-byte bound would refuse
/// every correct record. That mistake was caught once by a positive control on the capacity envelope.
pub const MAX_MOVE_SIGNATURE_BYTES_CHIRHO: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveStageIntentChirho {
    pub schema_chirho: String,
    /// Which move this is. Stage records from another move must not replay into this one.
    pub move_id_chirho: String,
    pub source_root_chirho: String,
    pub target_root_chirho: String,
    pub stage_chirho: MoveStageChirho,
    /// Content-address of the migration evidence this stage rests on.
    ///
    /// REQUIRED for `SurfacesCarriedChirho` and forbidden elsewhere. That stage is the one claiming a
    /// tenant's complete signed history, projections and audit coordinates arrived at the target, and a
    /// stage that claims it without naming the verification that says so is an assertion wearing a
    /// signature. Binding a digest points the claim at a specific artifact somebody can re-check — and
    /// a DIGEST rather than a path, because a root path in an append-only log is a host detail that
    /// outlives the host.
    pub surfaces_evidence_chirho: Option<String>,
    /// Full content-address of every signed stage record that may be appended after handoff.
    ///
    /// V2 fixes this grammar at exactly one record on `WriterHandedOffChirho`: the pre-authored
    /// `SourceRetiredChirho` attestation. Every other stage must carry an empty set. The store
    /// resolves and verifies that exact object before handoff and permits no control-object write
    /// afterwards, so the offline resume road cannot invent a terminal record after authority moved.
    pub post_handoff_record_digests_chirho: Vec<String>,
    /// Content address of the separately signed conditional retirement authorization.
    ///
    /// REQUIRED only on `SourceRetiredChirho`. The terminal stage is pre-authored, but its append is
    /// still conditional: the honest source recomputes the authorization's custody predicate after
    /// erasure and appends this exact record only when that result matches.
    pub retirement_authorization_digest_chirho: Option<String>,
    /// Monotone per move. The verifier is STATELESS and cannot check it; the durable store derives
    /// the high-water mark from the same retained rows it replays.
    pub stage_seq_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveStageAttestationChirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub intent_chirho: MoveStageIntentChirho,
    pub intent_digest_chirho: String,
    pub authority_key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveStageRefusalChirho {
    RecordSchemaMismatchChirho {
        found_chirho: String,
    },
    IntentSchemaMismatchChirho {
        found_chirho: String,
    },
    SignatureDomainMismatchChirho {
        found_chirho: String,
    },
    FieldTooLongChirho {
        field_chirho: String,
    },
    UnknownAuthorityKeyChirho {
        found_chirho: String,
    },
    IntentDigestMismatchChirho {
        declared_chirho: String,
        recomputed_chirho: String,
    },
    BadSignatureChirho,
    /// This record belongs to a different move.
    MoveMismatchChirho {
        expected_chirho: String,
        found_chirho: String,
    },
    /// A move whose source and target are the same root moves nothing and would retire the root it
    /// just handed to itself.
    SourceIsTargetChirho,
    /// `SurfacesCarriedChirho` without evidence: the stage that claims the tenant's history and
    /// projections arrived, claiming it about nothing.
    SurfacesCarriedWithoutEvidenceChirho,
    /// Carry evidence is content-addressed. An arbitrary non-empty string cannot carry that claim.
    SurfacesEvidenceDigestNotCanonicalChirho,
    /// Evidence attached to a stage that does not carry surfaces. Refused rather than ignored: a digest
    /// nobody checks is worse than none, because it reads as though something was verified.
    EvidenceOnANonCarryingStageChirho {
        stage_chirho: MoveStageChirho,
    },
    /// Handoff freezes the exact post-handoff grammar; V2 requires one terminal signed record.
    HandoffTerminalRecordCountChirho {
        found_chirho: usize,
    },
    /// Refuse an attacker-sized vector before serializing it into the recomputed intent digest.
    PostHandoffRecordPopulationExceededChirho {
        found_chirho: usize,
        max_chirho: usize,
    },
    /// A full signed-record content address must be canonical lowercase BLAKE3 hex.
    PostHandoffRecordDigestNotCanonicalChirho,
    /// Only the handoff record may carry the frozen post-handoff record population.
    PostHandoffRecordsOnWrongStageChirho {
        stage_chirho: MoveStageChirho,
    },
    /// A terminal stage without the conditional authorization would let attestation gate erasure.
    RetirementAuthorizationMissingChirho,
    /// The authorization reference must be a canonical lowercase BLAKE3 address.
    RetirementAuthorizationDigestNotCanonicalChirho,
    /// Only the terminal stage may name the retirement authorization.
    RetirementAuthorizationOnWrongStageChirho {
        stage_chirho: MoveStageChirho,
    },
}

/// A move stage that verified. Obtainable only through [`verify_move_stage_chirho`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMoveStageChirho {
    intent_chirho: MoveStageIntentChirho,
}

impl VerifiedMoveStageChirho {
    pub fn move_id_chirho(&self) -> &str {
        &self.intent_chirho.move_id_chirho
    }
    pub fn source_root_chirho(&self) -> &str {
        &self.intent_chirho.source_root_chirho
    }
    pub fn target_root_chirho(&self) -> &str {
        &self.intent_chirho.target_root_chirho
    }
    pub fn stage_chirho(&self) -> MoveStageChirho {
        self.intent_chirho.stage_chirho
    }
    pub fn stage_seq_chirho(&self) -> u64 {
        self.intent_chirho.stage_seq_chirho
    }
    pub fn intent_chirho(&self) -> &MoveStageIntentChirho {
        &self.intent_chirho
    }
}

/// A full signed move-control record verified before any namespace write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMoveControlRecordChirho {
    record_chirho: MoveStageAttestationChirho,
    verified_stage_chirho: VerifiedMoveStageChirho,
    record_digest_chirho: String,
}

impl VerifiedMoveControlRecordChirho {
    pub fn record_chirho(&self) -> &MoveStageAttestationChirho {
        &self.record_chirho
    }

    pub fn verified_stage_chirho(&self) -> &VerifiedMoveStageChirho {
        &self.verified_stage_chirho
    }

    pub fn record_digest_chirho(&self) -> &str {
        &self.record_digest_chirho
    }
}

/// Verifies a move authority's signature. No `sign_chirho`: the mover cannot author the evidence.
pub trait MoveAuthorityPortChirho {
    fn authority_key_id_chirho(&self) -> String;
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool;
}

pub fn move_stage_intent_digest_chirho(
    intent_chirho: &MoveStageIntentChirho,
) -> Result<String, MoveStageRefusalChirho> {
    hash_object_chirho(intent_chirho)
        .map(|hash_chirho| hash_chirho.0)
        .map_err(|_error_chirho| MoveStageRefusalChirho::BadSignatureChirho)
}

/// Content address of the complete signed record, including its signature.
pub fn move_stage_record_digest_chirho(
    record_chirho: &MoveStageAttestationChirho,
) -> Result<String, MoveStageRefusalChirho> {
    hash_object_chirho(record_chirho)
        .map(|hash_chirho| hash_chirho.0)
        .map_err(|_error_chirho| MoveStageRefusalChirho::BadSignatureChirho)
}

/// The exact bytes signed. Not unified with the other envelopes' builders: each names its own domain,
/// and a shared builder would let a record signed for one purpose verify for another.
pub fn unsigned_move_stage_message_chirho(record_chirho: &MoveStageAttestationChirho) -> String {
    format!(
        "{}|{}|{}|{}",
        record_chirho.signature_domain_chirho,
        record_chirho.schema_chirho,
        record_chirho.authority_key_id_chirho,
        record_chirho.intent_digest_chirho
    )
}

pub fn verify_move_stage_chirho(
    record_chirho: &MoveStageAttestationChirho,
    authority_chirho: &dyn MoveAuthorityPortChirho,
    expected_move_id_chirho: &str,
) -> Result<VerifiedMoveStageChirho, MoveStageRefusalChirho> {
    if record_chirho.schema_chirho != MOVE_STAGE_ATTESTATION_SCHEMA_V2_CHIRHO {
        return Err(MoveStageRefusalChirho::RecordSchemaMismatchChirho {
            found_chirho: record_chirho.schema_chirho.clone(),
        });
    }
    if record_chirho.intent_chirho.schema_chirho != MOVE_STAGE_INTENT_SCHEMA_V2_CHIRHO {
        return Err(MoveStageRefusalChirho::IntentSchemaMismatchChirho {
            found_chirho: record_chirho.intent_chirho.schema_chirho.clone(),
        });
    }
    if record_chirho.signature_domain_chirho != MOVE_STAGE_ATTESTATION_DOMAIN_V2_CHIRHO {
        return Err(MoveStageRefusalChirho::SignatureDomainMismatchChirho {
            found_chirho: record_chirho.signature_domain_chirho.clone(),
        });
    }
    for (field_chirho, value_chirho, bound_chirho) in [
        (
            "move_id_chirho",
            &record_chirho.intent_chirho.move_id_chirho,
            MAX_MOVE_TOKEN_BYTES_CHIRHO,
        ),
        (
            "source_root_chirho",
            &record_chirho.intent_chirho.source_root_chirho,
            MAX_MOVE_TOKEN_BYTES_CHIRHO,
        ),
        (
            "target_root_chirho",
            &record_chirho.intent_chirho.target_root_chirho,
            MAX_MOVE_TOKEN_BYTES_CHIRHO,
        ),
        (
            "authority_key_id_chirho",
            &record_chirho.authority_key_id_chirho,
            MAX_MOVE_TOKEN_BYTES_CHIRHO,
        ),
        (
            "intent_digest_chirho",
            &record_chirho.intent_digest_chirho,
            MAX_MOVE_TOKEN_BYTES_CHIRHO,
        ),
        (
            "sig_chirho",
            &record_chirho.sig_chirho,
            MAX_MOVE_SIGNATURE_BYTES_CHIRHO,
        ),
    ] {
        if value_chirho.len() > bound_chirho {
            return Err(MoveStageRefusalChirho::FieldTooLongChirho {
                field_chirho: field_chirho.to_string(),
            });
        }
    }
    if record_chirho
        .intent_chirho
        .surfaces_evidence_chirho
        .as_ref()
        .is_some_and(|evidence_chirho| evidence_chirho.len() > MAX_MOVE_TOKEN_BYTES_CHIRHO)
    {
        return Err(MoveStageRefusalChirho::FieldTooLongChirho {
            field_chirho: "surfaces_evidence_chirho".to_string(),
        });
    }
    if record_chirho
        .intent_chirho
        .post_handoff_record_digests_chirho
        .len()
        > MOVE_POST_HANDOFF_RECORD_COUNT_CHIRHO
    {
        return Err(
            MoveStageRefusalChirho::PostHandoffRecordPopulationExceededChirho {
                found_chirho: record_chirho
                    .intent_chirho
                    .post_handoff_record_digests_chirho
                    .len(),
                max_chirho: MOVE_POST_HANDOFF_RECORD_COUNT_CHIRHO,
            },
        );
    }
    if record_chirho
        .intent_chirho
        .post_handoff_record_digests_chirho
        .iter()
        .any(|digest_chirho| digest_chirho.len() > MAX_MOVE_TOKEN_BYTES_CHIRHO)
    {
        return Err(MoveStageRefusalChirho::FieldTooLongChirho {
            field_chirho: "post_handoff_record_digests_chirho".to_string(),
        });
    }
    if record_chirho
        .intent_chirho
        .retirement_authorization_digest_chirho
        .as_ref()
        .is_some_and(|digest_chirho| digest_chirho.len() > MAX_MOVE_TOKEN_BYTES_CHIRHO)
    {
        return Err(MoveStageRefusalChirho::FieldTooLongChirho {
            field_chirho: "retirement_authorization_digest_chirho".to_string(),
        });
    }
    if record_chirho.authority_key_id_chirho != authority_chirho.authority_key_id_chirho() {
        return Err(MoveStageRefusalChirho::UnknownAuthorityKeyChirho {
            found_chirho: record_chirho.authority_key_id_chirho.clone(),
        });
    }
    let recomputed_chirho = move_stage_intent_digest_chirho(&record_chirho.intent_chirho)?;
    if recomputed_chirho != record_chirho.intent_digest_chirho {
        return Err(MoveStageRefusalChirho::IntentDigestMismatchChirho {
            declared_chirho: record_chirho.intent_digest_chirho.clone(),
            recomputed_chirho,
        });
    }
    if !authority_chirho.verify_chirho(
        &unsigned_move_stage_message_chirho(record_chirho),
        &record_chirho.sig_chirho,
    ) {
        return Err(MoveStageRefusalChirho::BadSignatureChirho);
    }
    if record_chirho.intent_chirho.move_id_chirho != expected_move_id_chirho {
        return Err(MoveStageRefusalChirho::MoveMismatchChirho {
            expected_chirho: expected_move_id_chirho.to_string(),
            found_chirho: record_chirho.intent_chirho.move_id_chirho.clone(),
        });
    }
    if record_chirho.intent_chirho.source_root_chirho
        == record_chirho.intent_chirho.target_root_chirho
    {
        return Err(MoveStageRefusalChirho::SourceIsTargetChirho);
    }
    match (
        record_chirho.intent_chirho.stage_chirho,
        &record_chirho.intent_chirho.surfaces_evidence_chirho,
    ) {
        (MoveStageChirho::SurfacesCarriedChirho, None) => {
            return Err(MoveStageRefusalChirho::SurfacesCarriedWithoutEvidenceChirho)
        }
        (MoveStageChirho::SurfacesCarriedChirho, Some(evidence_chirho))
            if evidence_chirho.len() == MOVE_SURFACES_EVIDENCE_DIGEST_HEX_BYTES_CHIRHO
                && evidence_chirho.bytes().all(|byte_chirho| {
                    byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f')
                }) => {}
        (MoveStageChirho::SurfacesCarriedChirho, Some(_evidence_chirho)) => {
            return Err(MoveStageRefusalChirho::SurfacesEvidenceDigestNotCanonicalChirho)
        }
        (stage_chirho, Some(_evidence_chirho)) => {
            return Err(MoveStageRefusalChirho::EvidenceOnANonCarryingStageChirho { stage_chirho })
        }
        (_stage_chirho, None) => {}
    }
    match (
        record_chirho.intent_chirho.stage_chirho,
        record_chirho
            .intent_chirho
            .post_handoff_record_digests_chirho
            .as_slice(),
    ) {
        (MoveStageChirho::WriterHandedOffChirho, digests_chirho)
            if digests_chirho.len() != MOVE_POST_HANDOFF_RECORD_COUNT_CHIRHO =>
        {
            return Err(MoveStageRefusalChirho::HandoffTerminalRecordCountChirho {
                found_chirho: digests_chirho.len(),
            });
        }
        (MoveStageChirho::WriterHandedOffChirho, digests_chirho)
            if !digests_chirho.iter().all(|digest_chirho| {
                digest_chirho.len() == MOVE_SURFACES_EVIDENCE_DIGEST_HEX_BYTES_CHIRHO
                    && digest_chirho.bytes().all(|byte_chirho| {
                        byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f')
                    })
            }) =>
        {
            return Err(MoveStageRefusalChirho::PostHandoffRecordDigestNotCanonicalChirho);
        }
        (MoveStageChirho::WriterHandedOffChirho, _digests_chirho) => {}
        (_stage_chirho, []) => {}
        (stage_chirho, _digests_chirho) => {
            return Err(
                MoveStageRefusalChirho::PostHandoffRecordsOnWrongStageChirho { stage_chirho },
            );
        }
    }
    match (
        record_chirho.intent_chirho.stage_chirho,
        &record_chirho
            .intent_chirho
            .retirement_authorization_digest_chirho,
    ) {
        (MoveStageChirho::SourceRetiredChirho, None) => {
            return Err(MoveStageRefusalChirho::RetirementAuthorizationMissingChirho)
        }
        (MoveStageChirho::SourceRetiredChirho, Some(digest_chirho))
            if digest_chirho.len() == MOVE_SURFACES_EVIDENCE_DIGEST_HEX_BYTES_CHIRHO
                && digest_chirho.bytes().all(|byte_chirho| {
                    byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f')
                }) => {}
        (MoveStageChirho::SourceRetiredChirho, Some(_digest_chirho)) => {
            return Err(MoveStageRefusalChirho::RetirementAuthorizationDigestNotCanonicalChirho)
        }
        (stage_chirho, Some(_digest_chirho)) => {
            return Err(
                MoveStageRefusalChirho::RetirementAuthorizationOnWrongStageChirho { stage_chirho },
            )
        }
        (_stage_chirho, None) => {}
    }
    Ok(VerifiedMoveStageChirho {
        intent_chirho: record_chirho.intent_chirho.clone(),
    })
}

/// Verify a complete control record and bind the exact signed bytes to their content address.
pub fn verify_move_control_record_chirho(
    record_chirho: &MoveStageAttestationChirho,
    authority_chirho: &dyn MoveAuthorityPortChirho,
    expected_move_id_chirho: &str,
) -> Result<VerifiedMoveControlRecordChirho, MoveStageRefusalChirho> {
    let verified_stage_chirho =
        verify_move_stage_chirho(record_chirho, authority_chirho, expected_move_id_chirho)?;
    let record_digest_chirho = move_stage_record_digest_chirho(record_chirho)?;
    Ok(VerifiedMoveControlRecordChirho {
        record_chirho: record_chirho.clone(),
        verified_stage_chirho,
        record_digest_chirho,
    })
}

#[cfg(test)]
#[path = "move_attestation_tests_chirho.rs"]
mod move_attestation_tests_chirho;
