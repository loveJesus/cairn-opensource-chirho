// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! H2's fail-closed production admission views: exact static membership, an offline-issuer
//! verifier pin, and the rehearsal-only PlatformPolicy mint grant derived from the verified kind
//! registry. None of these views authors authority or reads ambient process state.

use cairn_config_chirho::config_chirho::{
    LedgerHostActivationPinConfigChirho, LedgerHostIssuerPinConfigChirho,
    LedgerHostMemberConfigChirho,
};
use cairn_kind_registry_chirho::chain_chirho::{IssuerVerifyViewChirho, VerifiedRegistryChirho};
use cairn_kind_registry_chirho::record_chirho::MintAuthorityRecordChirho;
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, MembershipStatusChirho,
    MembershipViewChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{AccountIdChirho, AssetKindIdChirho, DigestChirho};
use cairn_ledger_model_chirho::ShardEpochChirho;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostLedgerAuthorityRefusalChirho {
    EmptyMembershipChirho,
    DuplicateMemberChirho {
        owner_chirho: String,
    },
    InvalidIssuerKeyChirho,
    InvalidActivationKeyChirho,
    MembershipEpochRegressionChirho {
        current_epoch_chirho: ShardEpochChirho,
        requested_epoch_chirho: ShardEpochChirho,
    },
}

impl fmt::Display for HostLedgerAuthorityRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMembershipChirho => {
                formatter_chirho.write_str("static ledger membership must not be empty")
            }
            Self::DuplicateMemberChirho { owner_chirho } => write!(
                formatter_chirho,
                "static ledger membership repeats account owner {owner_chirho}"
            ),
            Self::InvalidIssuerKeyChirho => formatter_chirho
                .write_str("kind issuer verifying-key pin is not a valid Ed25519 point"),
            Self::InvalidActivationKeyChirho => formatter_chirho
                .write_str("ledger activation verifying-key pin is not a valid Ed25519 point"),
            Self::MembershipEpochRegressionChirho {
                current_epoch_chirho,
                requested_epoch_chirho,
            } => write!(
                formatter_chirho,
                "elected membership epoch cannot regress from {current_epoch_chirho} to {requested_epoch_chirho}"
            ),
        }
    }
}

impl Error for HostLedgerAuthorityRefusalChirho {}

/// The exact §11.0 cluster declaration for one local epoch. Another epoch is non-member rather
/// than implicitly current; dynamic membership remains a separately reviewed A6-family concern.
#[derive(Clone, Debug)]
pub struct StaticClusterMembershipChirho {
    local_epoch_chirho: ShardEpochChirho,
    members_chirho: Arc<HashSet<AccountIdChirho>>,
}

impl StaticClusterMembershipChirho {
    pub fn new_chirho(
        local_epoch_chirho: ShardEpochChirho,
        members_chirho: impl IntoIterator<Item = AccountIdChirho>,
    ) -> Result<Self, HostLedgerAuthorityRefusalChirho> {
        let mut unique_members_chirho = HashSet::new();
        for member_chirho in members_chirho {
            if !unique_members_chirho.insert(member_chirho.clone()) {
                return Err(HostLedgerAuthorityRefusalChirho::DuplicateMemberChirho {
                    owner_chirho: member_chirho.owner_chirho,
                });
            }
        }
        if unique_members_chirho.is_empty() {
            return Err(HostLedgerAuthorityRefusalChirho::EmptyMembershipChirho);
        }
        Ok(Self {
            local_epoch_chirho,
            members_chirho: Arc::new(unique_members_chirho),
        })
    }

    pub fn from_config_chirho(
        local_epoch_chirho: ShardEpochChirho,
        members_chirho: &[LedgerHostMemberConfigChirho],
    ) -> Result<Self, HostLedgerAuthorityRefusalChirho> {
        Self::new_chirho(
            local_epoch_chirho,
            members_chirho.iter().map(|member_chirho| AccountIdChirho {
                owner_chirho: member_chirho.owner_chirho.clone(),
                kind_id_chirho: AssetKindIdChirho(member_chirho.kind_id_chirho.clone()),
            }),
        )
    }

    pub fn local_epoch_chirho(&self) -> ShardEpochChirho {
        self.local_epoch_chirho
    }

    /// Build the exact-epoch A6 membership view while sharing the immutable roster in O(1).
    pub fn elected_view_chirho(&self) -> ElectedClusterMembershipChirho {
        ElectedClusterMembershipChirho {
            current_epoch_chirho: AtomicU64::new(self.local_epoch_chirho),
            members_chirho: Arc::clone(&self.members_chirho),
        }
    }
}

impl MembershipViewChirho for StaticClusterMembershipChirho {
    fn status_chirho(
        &self,
        account_chirho: &AccountIdChirho,
        epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        if epoch_chirho == self.local_epoch_chirho && self.members_chirho.contains(account_chirho) {
            MembershipStatusChirho::MemberChirho
        } else {
            MembershipStatusChirho::NonMemberChirho
        }
    }
}

/// A6's exact-current membership view. The roster is immutable and shared; only the elected
/// composite epoch advances. Admission therefore keeps expected O(1) account lookup without an
/// O(n) roster copy on every term or local regrant.
#[derive(Debug)]
pub struct ElectedClusterMembershipChirho {
    current_epoch_chirho: AtomicU64,
    members_chirho: Arc<HashSet<AccountIdChirho>>,
}

impl ElectedClusterMembershipChirho {
    pub fn current_epoch_chirho(&self) -> ShardEpochChirho {
        self.current_epoch_chirho.load(Ordering::Acquire)
    }

    pub fn rebind_epoch_chirho(
        &self,
        requested_epoch_chirho: ShardEpochChirho,
    ) -> Result<(), HostLedgerAuthorityRefusalChirho> {
        let mut current_epoch_chirho = self.current_epoch_chirho();
        loop {
            if requested_epoch_chirho < current_epoch_chirho {
                return Err(
                    HostLedgerAuthorityRefusalChirho::MembershipEpochRegressionChirho {
                        current_epoch_chirho,
                        requested_epoch_chirho,
                    },
                );
            }
            if requested_epoch_chirho == current_epoch_chirho {
                return Ok(());
            }
            match self.current_epoch_chirho.compare_exchange_weak(
                current_epoch_chirho,
                requested_epoch_chirho,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed_epoch_chirho) => current_epoch_chirho = observed_epoch_chirho,
            }
        }
    }

    #[cfg(any(test, feature = "test-hooks-chirho"))]
    pub fn shares_roster_with_chirho(
        &self,
        static_membership_chirho: &StaticClusterMembershipChirho,
    ) -> bool {
        Arc::ptr_eq(
            &self.members_chirho,
            &static_membership_chirho.members_chirho,
        )
    }
}

impl MembershipViewChirho for ElectedClusterMembershipChirho {
    fn status_chirho(
        &self,
        account_chirho: &AccountIdChirho,
        epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        if epoch_chirho == self.current_epoch_chirho()
            && self.members_chirho.contains(account_chirho)
        {
            MembershipStatusChirho::MemberChirho
        } else {
            MembershipStatusChirho::NonMemberChirho
        }
    }
}

/// Verifier-only issuer directory for the single platform issuer in this local-proof increment.
/// Debug can represent the principal and a fixed label, never raw public-key bytes.
pub struct PinnedKindIssuerVerifierChirho {
    principal_chirho: String,
    verifying_key_chirho: VerifyingKey,
}

impl fmt::Debug for PinnedKindIssuerVerifierChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("PinnedKindIssuerVerifierChirho")
            .field("principal_chirho", &self.principal_chirho)
            .field("verifying_key_chirho", &"<pinned-redacted-chirho>")
            .finish()
    }
}

impl PinnedKindIssuerVerifierChirho {
    pub fn from_config_chirho(
        config_chirho: &LedgerHostIssuerPinConfigChirho,
    ) -> Result<Self, HostLedgerAuthorityRefusalChirho> {
        let key_bytes_chirho = decode_hex_32_chirho(&config_chirho.verifying_key_hex_chirho)
            .filter(|bytes_chirho| bytes_chirho.iter().any(|byte_chirho| *byte_chirho != 0))
            .ok_or(HostLedgerAuthorityRefusalChirho::InvalidIssuerKeyChirho)?;
        let verifying_key_chirho = VerifyingKey::from_bytes(&key_bytes_chirho)
            .map_err(|_| HostLedgerAuthorityRefusalChirho::InvalidIssuerKeyChirho)?;
        Ok(Self {
            principal_chirho: config_chirho.principal_chirho.clone(),
            verifying_key_chirho,
        })
    }

    pub fn principal_chirho(&self) -> &str {
        &self.principal_chirho
    }
}

impl IssuerVerifyViewChirho for PinnedKindIssuerVerifierChirho {
    fn verify_issuer_chirho(
        &self,
        issuer_chirho: &str,
        signed_content_chirho: &str,
        sig_chirho: &str,
    ) -> bool {
        if issuer_chirho != self.principal_chirho {
            return false;
        }
        let Some(signature_bytes_chirho) = decode_hex_64_chirho(sig_chirho) else {
            return false;
        };
        self.verifying_key_chirho
            .verify(
                signed_content_chirho.as_bytes(),
                &Signature::from_bytes(&signature_bytes_chirho),
            )
            .is_ok()
    }
}

/// Verifier-only H3 activation authority. It verifies only caller-supplied canonical bytes; the
/// resident activation capsule separately reconstructs those bytes from fixed host coordinates and
/// the reviewed mint intent before trusting the signature.
pub struct PinnedLedgerActivationVerifierChirho {
    principal_chirho: String,
    verifying_key_chirho: VerifyingKey,
}

impl fmt::Debug for PinnedLedgerActivationVerifierChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("PinnedLedgerActivationVerifierChirho")
            .field("principal_chirho", &self.principal_chirho)
            .field("verifying_key_chirho", &"<pinned-redacted-chirho>")
            .finish()
    }
}

impl PinnedLedgerActivationVerifierChirho {
    pub fn from_config_chirho(
        config_chirho: &LedgerHostActivationPinConfigChirho,
    ) -> Result<Self, HostLedgerAuthorityRefusalChirho> {
        let key_bytes_chirho = decode_hex_32_chirho(&config_chirho.verifying_key_hex_chirho)
            .filter(|bytes_chirho| bytes_chirho.iter().any(|byte_chirho| *byte_chirho != 0))
            .ok_or(HostLedgerAuthorityRefusalChirho::InvalidActivationKeyChirho)?;
        let verifying_key_chirho = VerifyingKey::from_bytes(&key_bytes_chirho)
            .map_err(|_| HostLedgerAuthorityRefusalChirho::InvalidActivationKeyChirho)?;
        Ok(Self {
            principal_chirho: config_chirho.principal_chirho.clone(),
            verifying_key_chirho,
        })
    }

    pub fn principal_chirho(&self) -> &str {
        &self.principal_chirho
    }

    pub fn verify_canonical_statement_chirho(
        &self,
        principal_chirho: &str,
        canonical_statement_chirho: &[u8],
        signature_hex_chirho: &str,
    ) -> bool {
        if principal_chirho != self.principal_chirho {
            return false;
        }
        let Some(signature_bytes_chirho) = decode_hex_64_chirho(signature_hex_chirho) else {
            return false;
        };
        self.verifying_key_chirho
            .verify(
                canonical_statement_chirho,
                &Signature::from_bytes(&signature_bytes_chirho),
            )
            .is_ok()
    }
}

/// H2's served composition cannot mint or burn. Holding a trait object is not authority: every
/// evidence digest remains unverified.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClosedMintBurnAuthorityChirho;

impl AuthorityVerifierViewChirho for ClosedMintBurnAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::UnverifiedChirho
    }

    fn verify_burn_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::UnverifiedChirho
    }
}

/// H3's rehearsal-only mint authority. The existing admission door asks this view first; a signed
/// CURRENT PlatformPolicy ref is the grant. It never reads supply, and provider/burn authority is
/// deliberately absent.
#[derive(Clone, Copy, Debug)]
pub struct PlatformPolicyMintAuthorityChirho<'registry_chirho> {
    registry_chirho: &'registry_chirho VerifiedRegistryChirho,
}

impl<'registry_chirho> PlatformPolicyMintAuthorityChirho<'registry_chirho> {
    pub fn new_chirho(registry_chirho: &'registry_chirho VerifiedRegistryChirho) -> Self {
        Self { registry_chirho }
    }
}

impl AuthorityVerifierViewChirho for PlatformPolicyMintAuthorityChirho<'_> {
    fn verify_mint_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        for (candidate_kind_chirho, projection_chirho) in &self.registry_chirho.kinds_chirho {
            let current_matches_chirho = projection_chirho.current_ref_chirho.0 == *evidence_chirho;
            let superseded_matches_chirho = projection_chirho
                .superseded_refs_chirho
                .iter()
                .any(|policy_ref_chirho| policy_ref_chirho.0 == *evidence_chirho);
            if !current_matches_chirho && !superseded_matches_chirho {
                continue;
            }
            if candidate_kind_chirho != kind_id_chirho {
                return AuthorityVerdictChirho::WrongKindChirho;
            }
            if !current_matches_chirho {
                return AuthorityVerdictChirho::UnverifiedChirho;
            }
            return if matches!(
                projection_chirho
                    .current_policy_chirho
                    .mint_authority_chirho,
                MintAuthorityRecordChirho::PlatformPolicyChirho { .. }
            ) {
                AuthorityVerdictChirho::VerifiedChirho
            } else {
                AuthorityVerdictChirho::UnverifiedChirho
            };
        }
        AuthorityVerdictChirho::UnverifiedChirho
    }

    fn verify_burn_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::UnverifiedChirho
    }
}

fn decode_hex_32_chirho(encoded_chirho: &str) -> Option<[u8; 32]> {
    decode_hex_chirho(encoded_chirho)
}

fn decode_hex_64_chirho(encoded_chirho: &str) -> Option<[u8; 64]> {
    decode_hex_chirho(encoded_chirho)
}

fn decode_hex_chirho<const BYTES_CHIRHO: usize>(
    encoded_chirho: &str,
) -> Option<[u8; BYTES_CHIRHO]> {
    if encoded_chirho.len() != BYTES_CHIRHO * 2 || !encoded_chirho.is_ascii() {
        return None;
    }
    let mut decoded_chirho = [0_u8; BYTES_CHIRHO];
    for (index_chirho, byte_chirho) in decoded_chirho.iter_mut().enumerate() {
        let start_chirho = index_chirho * 2;
        *byte_chirho =
            u8::from_str_radix(&encoded_chirho[start_chirho..start_chirho + 2], 16).ok()?;
    }
    Some(decoded_chirho)
}
