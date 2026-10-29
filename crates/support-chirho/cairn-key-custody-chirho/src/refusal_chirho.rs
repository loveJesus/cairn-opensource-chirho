// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Every refusal the custody contract can name, each with one fixed sentence and never a value.
//!
//! An authority refusal keeps the mirror's own named reason (`mirror_identity_chirho`), because the
//! custody frames are admitted by the mirror's one authority check rather than a second copy of it.

use cairn_mirror_chirho::{MirrorContractErrorChirho, MirrorRefusalIdentityChirho};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyCustodyRefusalIdentityChirho {
    CustodyAnnouncementInvalidChirho,
    CustodyPointRejectedChirho,
    CustodyBindingMalformedChirho,
    CustodyHolderMismatchChirho,
    CustodySubjectMismatchChirho,
    CustodyKeyRecordMalformedChirho,
    CustodyUnwrapFailedChirho,
    CustodyFrameInvalidChirho,
    CustodyAuthorityRefusedChirho,
    CustodySubjectAlreadyErasedChirho,
    CustodyReceiptInvalidChirho,
    CustodyConfirmationIncompleteChirho,
    ErasureFrameInvalidChirho,
    ErasureReceiptInvalidChirho,
    ErasureReceiptNotForFrameChirho,
    ErasureRequirementInvalidChirho,
    ErasurePropagationContextInvalidChirho,
    ErasurePropagationRequirementInvalidChirho,
    ErasurePropagationBindingInvalidChirho,
    ErasurePropagationContextMismatchChirho,
    ErasurePropagationSuccessionInvalidChirho,
    DecommissionAttestationInvalidChirho,
    DecommissionHolderStillPlacedChirho,
    CustodyWireInvalidChirho,
}

impl KeyCustodyRefusalIdentityChirho {
    /// The one fixed sentence for each refusal.
    pub fn sentence_chirho(self) -> &'static str {
        match self {
            Self::CustodyAnnouncementInvalidChirho => {
                "a custody announcement is not in form or not signed by its node"
            }
            Self::CustodyPointRejectedChirho => "a custody public key is a rejected point",
            Self::CustodyBindingMalformedChirho => "a custody binding is not in form",
            Self::CustodyHolderMismatchChirho => "the key is bound to another holder",
            Self::CustodySubjectMismatchChirho => "a key record's subject is not the bound one",
            Self::CustodyKeyRecordMalformedChirho => "a key record is not in form",
            Self::CustodyUnwrapFailedChirho => "a wrapped key does not open for this holder",
            Self::CustodyFrameInvalidChirho => {
                "a custody frame is not in form, not bound by its digest, or not signed by its sender"
            }
            Self::CustodyAuthorityRefusedChirho => {
                "the sender is not the current elected leader of this holder's exact view"
            }
            Self::CustodySubjectAlreadyErasedChirho => {
                "the key or its subject is already erased on this holder"
            }
            Self::CustodyReceiptInvalidChirho => {
                "a custody receipt is not in form or not signed by its holder"
            }
            Self::CustodyConfirmationIncompleteChirho => {
                "custody is not confirmed by every other placement holder"
            }
            Self::ErasureFrameInvalidChirho => {
                "an erasure frame is not in form, not bound by its digest, or not signed by its sender"
            }
            Self::ErasureReceiptInvalidChirho => {
                "an erasure receipt does not account for exactly the frame's key ids or is not signed"
            }
            Self::ErasureReceiptNotForFrameChirho => {
                "an erasure receipt does not answer the frame it was sent for"
            }
            Self::ErasureRequirementInvalidChirho => "an erasure requirement is not in form",
            Self::ErasurePropagationContextInvalidChirho => {
                "an erasure propagation context is not in form"
            }
            Self::ErasurePropagationRequirementInvalidChirho => {
                "an erasure propagation requirement is not in form, not bound by its digest, or not signed by its issuer"
            }
            Self::ErasurePropagationBindingInvalidChirho => {
                "an erasure propagation binding is not in form, names another requirement, or is not signed by its issuer"
            }
            Self::ErasurePropagationContextMismatchChirho => {
                "an erasure propagation record is for another group, lineage or issuer"
            }
            Self::ErasurePropagationSuccessionInvalidChirho => {
                "a successor requirement does not carry its predecessor exactly"
            }
            Self::DecommissionAttestationInvalidChirho => {
                "a decommission attestation is not in form or not signed by its leader"
            }
            Self::DecommissionHolderStillPlacedChirho => {
                "a holder cannot be attested destroyed while the placement still names it"
            }
            Self::CustodyWireInvalidChirho => "a custody wire message is not in form or too large",
        }
    }
}

/// A refusal: its identity, the mirror's reason when the mirror's authority check refused, and a
/// fixed detail. None of them ever carries a key, a subject or ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyCustodyErrorChirho {
    identity_chirho: KeyCustodyRefusalIdentityChirho,
    mirror_identity_chirho: Option<MirrorRefusalIdentityChirho>,
    detail_chirho: &'static str,
}

impl KeyCustodyErrorChirho {
    pub fn new_chirho(
        identity_chirho: KeyCustodyRefusalIdentityChirho,
        detail_chirho: &'static str,
    ) -> Self {
        Self {
            identity_chirho,
            mirror_identity_chirho: None,
            detail_chirho,
        }
    }

    /// The mirror's authority check refused: keep its named reason.
    pub fn from_mirror_authority_chirho(error_chirho: MirrorContractErrorChirho) -> Self {
        Self {
            identity_chirho: KeyCustodyRefusalIdentityChirho::CustodyAuthorityRefusedChirho,
            mirror_identity_chirho: Some(error_chirho.identity_chirho()),
            detail_chirho: error_chirho.detail_chirho(),
        }
    }

    pub fn identity_chirho(&self) -> KeyCustodyRefusalIdentityChirho {
        self.identity_chirho
    }

    pub fn mirror_identity_chirho(&self) -> Option<MirrorRefusalIdentityChirho> {
        self.mirror_identity_chirho
    }

    pub fn detail_chirho(&self) -> &'static str {
        self.detail_chirho
    }
}

impl fmt::Display for KeyCustodyErrorChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter_chirho,
            "{:?}: {}",
            self.identity_chirho,
            self.identity_chirho.sentence_chirho()
        )?;
        if let Some(mirror_chirho) = self.mirror_identity_chirho {
            write!(formatter_chirho, " [{}]", mirror_chirho.as_str_chirho())?;
        }
        write!(formatter_chirho, " ({})", self.detail_chirho)
    }
}

impl std::error::Error for KeyCustodyErrorChirho {}

pub(crate) fn refuse_chirho(
    identity_chirho: KeyCustodyRefusalIdentityChirho,
    detail_chirho: &'static str,
) -> KeyCustodyErrorChirho {
    KeyCustodyErrorChirho::new_chirho(identity_chirho, detail_chirho)
}
