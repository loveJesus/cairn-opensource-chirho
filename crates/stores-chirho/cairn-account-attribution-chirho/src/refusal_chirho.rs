// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The named refusals of the attribution store, each with one fixed sentence, carried inside `anyhow` so a caller can downcast to the identity.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountAttributionRefusalChirho {
    /// The principal or a coordinate is not in form.
    AccountCoordinateInvalidChirho,
    /// A subject, key id or reason is not in form.
    AttributionFieldInvalidChirho,
    /// The account is frozen, so no new key may be attributed to it.
    AccountFrozenChirho,
    /// The account is not frozen, so its inventory could still grow and is not readable.
    AccountNotFrozenChirho,
    /// A stored attribution or freeze record is malformed, out of sequence, for another account, or not
    /// signed by this root.
    AttributionRecordUnverifiedChirho,
    /// The subject already belongs to another owner, so erasing it would shred that owner's keys too.
    SubjectOwnedElsewhereChirho,
    /// The subject lies in a principal's namespace, and only that principal's account may own it.
    SubjectNamespaceReservedChirho,
    /// The subject was claimed, but its owner record is missing, so a fresh claim could hand an earlier
    /// owner's keys to a new one. It needs a verified migration.
    SubjectOwnerRecordMissingChirho,
}

impl AccountAttributionRefusalChirho {
    pub fn sentence_chirho(self) -> &'static str {
        match self {
            Self::AccountCoordinateInvalidChirho => {
                "the account principal or coordinate is not in form"
            }
            Self::AttributionFieldInvalidChirho => {
                "an attribution subject, key id or reason is not in form"
            }
            Self::AccountFrozenChirho => {
                "the account is frozen; no new key may be attributed to it"
            }
            Self::AccountNotFrozenChirho => {
                "the account is not frozen, so its inventory could still grow"
            }
            Self::AttributionRecordUnverifiedChirho => {
                "a stored attribution or freeze record does not verify"
            }
            Self::SubjectOwnedElsewhereChirho => {
                "the subject belongs to another owner; no key of this owner may join it"
            }
            Self::SubjectNamespaceReservedChirho => {
                "the subject is in a principal's namespace; only that principal's account may own it"
            }
            Self::SubjectOwnerRecordMissingChirho => {
                "the subject was claimed but its owner record is missing; it needs a verified migration"
            }
        }
    }
}

/// A refusal: its identity and a fixed detail. Neither carries a principal, subject or key id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountAttributionErrorChirho {
    pub identity_chirho: AccountAttributionRefusalChirho,
    pub detail_chirho: &'static str,
}

impl fmt::Display for AccountAttributionErrorChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter_chirho,
            "{:?}: {} ({})",
            self.identity_chirho,
            self.identity_chirho.sentence_chirho(),
            self.detail_chirho
        )
    }
}

impl std::error::Error for AccountAttributionErrorChirho {}

pub(crate) fn refuse_chirho(
    identity_chirho: AccountAttributionRefusalChirho,
    detail_chirho: &'static str,
) -> anyhow::Error {
    anyhow::Error::new(AccountAttributionErrorChirho {
        identity_chirho,
        detail_chirho,
    })
}
