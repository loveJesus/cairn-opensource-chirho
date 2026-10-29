// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! What a caller of erasure propagation keeps: an attempt's identity, which it may store and hand back, and the attempt, a status snapshot of that one requirement which only this crate builds from a verified load.
//!
//! C5 B3-a4-i (design item 17; design GOs gpt #30296, agy #30332). The identity is coordinates only: the
//! store's group and lineage, the subject, the erasure record the requirement is bound to, and the
//! requirement's own digest. It deserializes, so a caller can keep it, and it is never trusted on its own:
//! every use finds the requirement again by its digest in the subject's verified view, never by a seq, and
//! checks every other coordinate against what the store verified. The attempt adds B1's status over that
//! requirement's STORED receipts, which stays inside this crate because it names holders: a caller reads the
//! identity and completeness only. Its completeness is requirement-scoped snapshot evidence: every holder in
//! the requirement's STORED holder set is closed. It is not the subject's closure, and it says nothing about a
//! holder outside that set (gpt #30286, #30296). R3 still owes item 9's conjunction and C5.4, and its elected
//! erasure refusal stays CLOSED.

use super::{
    unreadable_chirho, ErasurePropagationStoreChirho, LoadedSubjectChirho,
    RequirementStandingChirho, SubjectPropagationViewChirho, DIGEST_HEX_LEN_CHIRHO,
};
use crate::leader_chirho::refusal_chirho::{LeaderRefusalChirho, LeaderRefusalIdentityChirho};
use crate::private_tree_chirho::hex_chirho;
use cairn_key_custody_chirho::{
    ErasureStatusChirho, VerifiedErasurePropagationBindingChirho,
    VerifiedErasurePropagationRequirementChirho,
};
use cairn_mirror_chirho::MirrorMembershipViewChirho;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The coordinates of one propagation attempt. A caller may keep them and hand them back to
/// `retry_erasure_propagation_chirho`; they are never trusted on their own, and every use re-derives
/// everything from the store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureAttemptIdentityChirho {
    pub consistency_group_digest_chirho: String,
    pub tenant_id_chirho: String,
    pub genesis_instance_id_chirho: String,
    pub subject_digest_chirho: String,
    /// The digest of the root's erasure record the requirement is bound to.
    pub erasure_record_digest_chirho: String,
    pub requirement_digest_chirho: String,
}

/// One attempt as the store held it when it was read: its identity, and B1's status over its ONE
/// requirement's stored receipts. Only this crate builds one, from a verified load. A caller reads its
/// identity and whether it is complete. The holders behind that answer stay inside this crate (item 14 (5),
/// gpt #30365), so neither a public accessor nor `Debug` names a holder.
///
/// Anyone can deserialize and build an identity, and read an attempt's identity and completeness. That is the
/// control for the three examples after it:
///
/// ```
/// fn needs_deserialize_chirho<T: serde::de::DeserializeOwned>() {}
/// needs_deserialize_chirho::<cairn_key_custody_http_chirho::ErasureAttemptIdentityChirho>();
/// let _identity_chirho = cairn_key_custody_http_chirho::ErasureAttemptIdentityChirho {
///     consistency_group_digest_chirho: String::new(),
///     tenant_id_chirho: String::new(),
///     genesis_instance_id_chirho: String::new(),
///     subject_digest_chirho: String::new(),
///     erasure_record_digest_chirho: String::new(),
///     requirement_digest_chirho: String::new(),
/// };
/// let _status_chirho =
///     cairn_key_custody_chirho::ErasureStatusChirho::ErasureConfirmedByHolderReceiptsChirho;
/// fn read_chirho(attempt_chirho: &cairn_key_custody_http_chirho::ErasureAttemptChirho) -> bool {
///     let _ = attempt_chirho.identity_chirho();
///     attempt_chirho.is_complete_chirho()
/// }
/// ```
///
/// A caller cannot deserialize an attempt:
///
/// ```compile_fail
/// fn needs_deserialize_chirho<T: serde::de::DeserializeOwned>() {}
/// needs_deserialize_chirho::<cairn_key_custody_http_chirho::ErasureAttemptChirho>();
/// ```
///
/// Nor build one, because its fields are private:
///
/// ```compile_fail
/// fn forge_chirho(
///     identity_chirho: cairn_key_custody_http_chirho::ErasureAttemptIdentityChirho,
/// ) -> cairn_key_custody_http_chirho::ErasureAttemptChirho {
///     cairn_key_custody_http_chirho::ErasureAttemptChirho {
///         identity_chirho,
///         status_chirho:
///             cairn_key_custody_chirho::ErasureStatusChirho::ErasureConfirmedByHolderReceiptsChirho,
///     }
/// }
/// ```
///
/// Nor read its status, whose pending and attested sets name holders:
///
/// ```compile_fail
/// fn read_chirho(attempt_chirho: &cairn_key_custody_http_chirho::ErasureAttemptChirho) {
///     let _ = attempt_chirho.status_chirho();
/// }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct ErasureAttemptChirho {
    identity_chirho: ErasureAttemptIdentityChirho,
    status_chirho: ErasureStatusChirho,
}

impl ErasureAttemptChirho {
    pub fn identity_chirho(&self) -> &ErasureAttemptIdentityChirho {
        &self.identity_chirho
    }

    /// B1's status over the requirement's stored receipts, under the view it was read with. Its pending and
    /// attested sets name holders, so only this crate's arms read it.
    #[cfg(test)]
    pub(crate) fn status_chirho(&self) -> &ErasureStatusChirho {
        &self.status_chirho
    }

    /// Whether every holder in this requirement's STORED holder set is closed. It is not the subject's
    /// closure, and it is not coverage of any holder outside that set.
    pub fn is_complete_chirho(&self) -> bool {
        self.status_chirho.is_complete_chirho()
    }
}

/// The identity and whether the attempt is complete, never the holders behind that answer.
impl fmt::Debug for ErasureAttemptChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("ErasureAttemptChirho")
            .field("identity_chirho", &self.identity_chirho)
            .field("complete_chirho", &self.is_complete_chirho())
            .finish_non_exhaustive()
    }
}

impl ErasurePropagationStoreChirho {
    /// The attempt for the bound requirement whose binding names `erasure_record_digest_chirho`, which is what
    /// the root holds right after its append, with B1's status under the caller's current view. Exactly one
    /// bound requirement may name it: none is unknown, and more than one is state this store never writes.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
    pub fn erasure_attempt_chirho(
        &self,
        subject_digest_chirho: &str,
        erasure_record_digest_chirho: &str,
        current_view_chirho: &MirrorMembershipViewChirho,
    ) -> Result<ErasureAttemptChirho, LeaderRefusalChirho> {
        self.with_store_lock_chirho(|| {
            let loaded_chirho = self.load_subject_chirho(subject_digest_chirho)?;
            let mut naming_chirho =
                loaded_chirho
                    .bindings_chirho
                    .iter()
                    .filter(|(_, binding_chirho)| {
                        binding_chirho.erasure_record_digest_chirho()
                            == erasure_record_digest_chirho
                    });
            let (seq_chirho, binding_chirho) = naming_chirho
                .next()
                .ok_or(LeaderRefusalIdentityChirho::ErasureAttemptUnknownChirho)?;
            if naming_chirho.next().is_some() {
                return Err(unreadable_chirho());
            }
            // A binding sits only beside its requirement: the load refuses one without it.
            let requirement_chirho = &loaded_chirho.requirements_chirho[seq_chirho];
            self.attempt_locked_chirho(
                &loaded_chirho,
                requirement_chirho,
                binding_chirho,
                current_view_chirho,
            )
        })
    }

    /// The attempt the identity names, read afresh: its requirement found again by digest in the subject's
    /// verified view, every coordinate checked, and B1's status over its stored receipts under the caller's
    /// current view.
    pub(crate) fn attempt_for_identity_chirho(
        &self,
        identity_chirho: &ErasureAttemptIdentityChirho,
        current_view_chirho: &MirrorMembershipViewChirho,
    ) -> Result<ErasureAttemptChirho, LeaderRefusalChirho> {
        self.check_attempt_context_chirho(identity_chirho)?;
        self.with_store_lock_chirho(|| {
            let loaded_chirho = self.load_subject_chirho(&identity_chirho.subject_digest_chirho)?;
            let view_chirho = loaded_chirho.view_chirho();
            let (requirement_chirho, binding_chirho) =
                requirement_for_identity_chirho(&view_chirho, identity_chirho)?;
            self.attempt_locked_chirho(
                &loaded_chirho,
                requirement_chirho,
                binding_chirho,
                current_view_chirho,
            )
        })
    }

    /// Refuse, before anything is read, an identity for another group, tenant or genesis instance than this
    /// store's, or one whose subject is not a digest, so a bad identity is never read as a damaged store.
    pub(crate) fn check_attempt_context_chirho(
        &self,
        identity_chirho: &ErasureAttemptIdentityChirho,
    ) -> Result<(), LeaderRefusalChirho> {
        if identity_chirho.consistency_group_digest_chirho
            != self.context_chirho.consistency_group_digest_chirho()
            || identity_chirho.tenant_id_chirho != self.context_chirho.tenant_id_chirho()
            || identity_chirho.genesis_instance_id_chirho
                != self.context_chirho.genesis_instance_id_chirho()
        {
            return Err(LeaderRefusalIdentityChirho::ErasureAttemptContextMismatchChirho.into());
        }
        if hex_chirho(
            &identity_chirho.subject_digest_chirho,
            DIGEST_HEX_LEN_CHIRHO,
        )
        .is_err()
        {
            return Err(LeaderRefusalIdentityChirho::ErasureAttemptUnknownChirho.into());
        }
        Ok(())
    }

    /// The identity of a bound requirement: this store's group and lineage, and the requirement's own
    /// coordinates.
    pub(crate) fn attempt_identity_chirho(
        &self,
        requirement_chirho: &VerifiedErasurePropagationRequirementChirho,
        binding_chirho: &VerifiedErasurePropagationBindingChirho,
    ) -> ErasureAttemptIdentityChirho {
        ErasureAttemptIdentityChirho {
            consistency_group_digest_chirho: self
                .context_chirho
                .consistency_group_digest_chirho()
                .to_string(),
            tenant_id_chirho: self.context_chirho.tenant_id_chirho().to_string(),
            genesis_instance_id_chirho: self
                .context_chirho
                .genesis_instance_id_chirho()
                .to_string(),
            subject_digest_chirho: requirement_chirho.subject_digest_chirho().to_string(),
            erasure_record_digest_chirho: binding_chirho.erasure_record_digest_chirho().to_string(),
            requirement_digest_chirho: requirement_chirho.requirement_digest_chirho().to_string(),
        }
    }

    fn attempt_locked_chirho(
        &self,
        loaded_chirho: &LoadedSubjectChirho,
        requirement_chirho: &VerifiedErasurePropagationRequirementChirho,
        binding_chirho: &VerifiedErasurePropagationBindingChirho,
        current_view_chirho: &MirrorMembershipViewChirho,
    ) -> Result<ErasureAttemptChirho, LeaderRefusalChirho> {
        let status_chirho = self.bound_status_locked_chirho(
            loaded_chirho,
            requirement_chirho.erasure_seq_chirho(),
            requirement_chirho,
            current_view_chirho,
        )?;
        Ok(ErasureAttemptChirho {
            identity_chirho: self.attempt_identity_chirho(requirement_chirho, binding_chirho),
            status_chirho,
        })
    }
}

/// The bound requirement an attempt's identity names in a subject's verified view, with its binding, found by
/// its requirement digest and never by a seq. A carried requirement refuses by its own name, never as the
/// generic unbound refusal (gpt #30286), and a bound one must be bound to exactly the identity's erasure record,
/// so an identity can never steer a retry onto another erasure.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`, section 4.
pub(crate) fn requirement_for_identity_chirho<'view_chirho>(
    view_chirho: &'view_chirho SubjectPropagationViewChirho,
    identity_chirho: &ErasureAttemptIdentityChirho,
) -> Result<
    (
        &'view_chirho VerifiedErasurePropagationRequirementChirho,
        &'view_chirho VerifiedErasurePropagationBindingChirho,
    ),
    LeaderRefusalChirho,
> {
    let (requirement_chirho, standing_chirho) = view_chirho
        .entries_chirho()
        .iter()
        .find(|(requirement_chirho, _)| {
            requirement_chirho.requirement_digest_chirho()
                == identity_chirho.requirement_digest_chirho
        })
        .ok_or(LeaderRefusalIdentityChirho::ErasureAttemptUnknownChirho)?;
    match standing_chirho {
        RequirementStandingChirho::CarriedByChirho { .. } => {
            Err(LeaderRefusalIdentityChirho::ErasureAttemptCarriedChirho.into())
        }
        RequirementStandingChirho::PendingChirho => {
            Err(LeaderRefusalIdentityChirho::ErasurePropagationRequirementUnboundChirho.into())
        }
        RequirementStandingChirho::BoundChirho(binding_chirho) => {
            if binding_chirho.erasure_record_digest_chirho()
                != identity_chirho.erasure_record_digest_chirho
            {
                return Err(LeaderRefusalIdentityChirho::ErasureAttemptRecordMismatchChirho.into());
            }
            Ok((requirement_chirho, binding_chirho.as_ref()))
        }
    }
}
