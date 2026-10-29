// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Every refusal a key-custody holder answers with: the custody contract's own, or one of the holder's, always a fixed name and never a key, subject or path.

use cairn_key_custody_chirho::KeyCustodyErrorChirho;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HolderRefusalIdentityChirho {
    /// The frame's term is below the highest term this holder already accepted for its group.
    HolderStaleTermChirho,
    /// A stored binding or key for this key id differs from the frame's coordinates or bytes.
    HolderCustodyConflictChirho,
    /// A key file is stored without its binding, which custody never leaves behind.
    HolderKeyWithoutBindingChirho,
    /// An erasure removed a key whose stored binding is missing or unreadable, so its coverage cannot
    /// be verified and this holder's share stays pending.
    HolderErasureBindingUnverifiableChirho,
    /// A subject's key directory holds more entries than one erasure may scan.
    HolderErasureScanTooLargeChirho,
    /// The holder's stored state is unreadable, out of form, or not where it belongs.
    HolderStoreUnreadableChirho,
    /// A durable write or removal did not complete.
    HolderStoreWriteFailedChirho,
    /// The node's existing key could not sign, or it is not this holder's node key.
    HolderSignerUnavailableChirho,
    /// The admission stopped without an answer, so its durable effect is unknown; the leader retries.
    HolderAdmissionInterruptedChirho,
}

impl HolderRefusalIdentityChirho {
    pub fn as_str_chirho(self) -> &'static str {
        match self {
            Self::HolderStaleTermChirho => "HolderStaleTermChirho",
            Self::HolderCustodyConflictChirho => "HolderCustodyConflictChirho",
            Self::HolderKeyWithoutBindingChirho => "HolderKeyWithoutBindingChirho",
            Self::HolderErasureBindingUnverifiableChirho => {
                "HolderErasureBindingUnverifiableChirho"
            }
            Self::HolderErasureScanTooLargeChirho => "HolderErasureScanTooLargeChirho",
            Self::HolderStoreUnreadableChirho => "HolderStoreUnreadableChirho",
            Self::HolderStoreWriteFailedChirho => "HolderStoreWriteFailedChirho",
            Self::HolderSignerUnavailableChirho => "HolderSignerUnavailableChirho",
            Self::HolderAdmissionInterruptedChirho => "HolderAdmissionInterruptedChirho",
        }
    }

    /// Whether the refusal is the holder failing rather than refusing the frame.
    pub fn is_internal_chirho(self) -> bool {
        matches!(
            self,
            Self::HolderStoreUnreadableChirho
                | Self::HolderStoreWriteFailedChirho
                | Self::HolderSignerUnavailableChirho
                | Self::HolderAdmissionInterruptedChirho
        )
    }
}

/// A holder's refusal: the custody contract refused the frame, or the holder refused or failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HolderRefusalChirho {
    ContractChirho(KeyCustodyErrorChirho),
    HolderChirho(HolderRefusalIdentityChirho),
}

impl HolderRefusalChirho {
    /// The fixed name the endpoint answers with. A contract refusal on authority also names the
    /// mirror's own reason, after a colon.
    pub fn wire_identity_chirho(&self) -> String {
        match self {
            Self::ContractChirho(error_chirho) => match error_chirho.mirror_identity_chirho() {
                Some(mirror_chirho) => format!(
                    "{:?}:{}",
                    error_chirho.identity_chirho(),
                    mirror_chirho.as_str_chirho()
                ),
                None => format!("{:?}", error_chirho.identity_chirho()),
            },
            Self::HolderChirho(identity_chirho) => identity_chirho.as_str_chirho().to_string(),
        }
    }

    pub fn holder_identity_chirho(&self) -> Option<HolderRefusalIdentityChirho> {
        match self {
            Self::ContractChirho(_) => None,
            Self::HolderChirho(identity_chirho) => Some(*identity_chirho),
        }
    }

    pub fn is_internal_chirho(&self) -> bool {
        self.holder_identity_chirho()
            .is_some_and(HolderRefusalIdentityChirho::is_internal_chirho)
    }
}

impl From<KeyCustodyErrorChirho> for HolderRefusalChirho {
    fn from(error_chirho: KeyCustodyErrorChirho) -> Self {
        Self::ContractChirho(error_chirho)
    }
}

impl From<HolderRefusalIdentityChirho> for HolderRefusalChirho {
    fn from(identity_chirho: HolderRefusalIdentityChirho) -> Self {
        Self::HolderChirho(identity_chirho)
    }
}

impl fmt::Display for HolderRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(&self.wire_identity_chirho())
    }
}

impl std::error::Error for HolderRefusalChirho {}
