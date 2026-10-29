// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The signer boundary (design section 8): the dual-key trust split, its message classes with
//! domain separation, Ed25519 curve-point validation, the custody-supplied expected-key pins, and the
//! role-bound existing-key-only signer that refuses a message class its role does not own. This crate
//! signs with EXISTING keys only and calls no key generator (no generation call site, no RNG in scope; never-generate is enforced by the 8.2c source-census guard, not by compile-time gating, since ed25519-dalek rand_core is feature-unified workspace-wide); no key or key id from a plan or
//! packet can select a verifier.

use crate::error_chirho::{GeoGenesisRefusalChirho, GeoGenesisResultChirho};
use crate::ruling_chirho::GeoGenesisTrustProfileChirho;
use crate::scalar_chirho::{GeoEd25519PublicKeyChirho, GeoEd25519SignatureChirho};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fmt;
use std::path::Path;
use zeroize::Zeroizing;

/// Which operator authority a signer holds (design section 8). Member keys are always selected from
/// the verified topology, never from a receipt or a pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GeoSignerRoleChirho {
    /// Signs the plan, the intent marker, and the operator-guard marker receipt.
    PlanAuthorityChirho,
    /// Signs the authoritative root-publication receipt and the final acceptance packet.
    AcceptanceAuthorityChirho,
    /// A planned member: signs only its own marker and member-admission receipts.
    MemberChirho,
    /// The operator custody root that attests custody-domain identities (ruling 1).
    CustodyAuthorityChirho,
}

/// The exact canonical message class a signature covers. Each class is domain-separated by a distinct
/// tag, so a signature made for one class can never verify for another even under the same key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GeoGenesisMessageClassChirho {
    PlanChirho,
    IntentMarkerChirho,
    OperatorGuardMarkerReceiptChirho,
    MemberMarkerReceiptChirho,
    PublicationReceiptChirho,
    MemberAdmissionReceiptChirho,
    AcceptanceChirho,
    CustodyAttestationChirho,
}

impl GeoGenesisMessageClassChirho {
    /// The role that alone may sign this class (design section 8 message-class ownership).
    pub fn owning_role_chirho(self) -> GeoSignerRoleChirho {
        match self {
            Self::PlanChirho
            | Self::IntentMarkerChirho
            | Self::OperatorGuardMarkerReceiptChirho => GeoSignerRoleChirho::PlanAuthorityChirho,
            Self::PublicationReceiptChirho | Self::AcceptanceChirho => {
                GeoSignerRoleChirho::AcceptanceAuthorityChirho
            }
            Self::MemberMarkerReceiptChirho | Self::MemberAdmissionReceiptChirho => {
                GeoSignerRoleChirho::MemberChirho
            }
            Self::CustodyAttestationChirho => GeoSignerRoleChirho::CustodyAuthorityChirho,
        }
    }

    /// The fixed domain-separation tag prepended (with a NUL) to the unsigned canonical bytes before
    /// signing/verifying. NUL cannot appear in an ASCII tag or in canonical JSON, so the framing is
    /// unambiguous and the tag cannot be confused with the record body.
    fn domain_tag_chirho(self) -> &'static str {
        match self {
            Self::PlanChirho => "cairn-geo-genesis/plan-v1-chirho",
            Self::IntentMarkerChirho => "cairn-geo-genesis/intent-marker-v1-chirho",
            Self::OperatorGuardMarkerReceiptChirho => {
                "cairn-geo-genesis/operator-guard-marker-receipt-v1-chirho"
            }
            Self::MemberMarkerReceiptChirho => "cairn-geo-genesis/member-marker-receipt-v1-chirho",
            Self::PublicationReceiptChirho => "cairn-geo-genesis/publication-receipt-v1-chirho",
            Self::MemberAdmissionReceiptChirho => {
                "cairn-geo-genesis/member-admission-receipt-v1-chirho"
            }
            Self::AcceptanceChirho => "cairn-geo-genesis/acceptance-v1-chirho",
            Self::CustodyAttestationChirho => "cairn-geo-genesis/custody-attestation-v1-chirho",
        }
    }
}

/// The domain-separated signing/verification input: `tag \0 unsigned_canonical_bytes`.
fn domain_separated_message_chirho(
    class_chirho: GeoGenesisMessageClassChirho,
    unsigned_bytes_chirho: &[u8],
) -> Vec<u8> {
    let tag_chirho = class_chirho.domain_tag_chirho();
    let mut message_chirho = Vec::with_capacity(tag_chirho.len() + 1 + unsigned_bytes_chirho.len());
    message_chirho.extend_from_slice(tag_chirho.as_bytes());
    message_chirho.push(0u8);
    message_chirho.extend_from_slice(unsigned_bytes_chirho);
    message_chirho
}

/// Decode a public key as a valid Ed25519 curve point, or refuse. This is the curve-point validation
/// deferred from 8.2a; a 32-byte value that is not on the curve refuses here.
pub(crate) fn curve_point_verifying_key_chirho(
    key_chirho: &GeoEd25519PublicKeyChirho,
) -> GeoGenesisResultChirho<VerifyingKey> {
    VerifyingKey::from_bytes(key_chirho.as_bytes_chirho())
        .map_err(|_error_chirho| GeoGenesisRefusalChirho::NonCurvePointKeyChirho)
}

/// Verify a signature against the custody-supplied expected key over the domain-separated class
/// message. The key is curve-validated first; `verify_strict` rejects non-canonical/small-order
/// encodings. The caller supplies the expected key from custody config — never from the artifact.
pub(crate) fn verify_class_signature_chirho(
    expected_key_chirho: &GeoEd25519PublicKeyChirho,
    class_chirho: GeoGenesisMessageClassChirho,
    unsigned_bytes_chirho: &[u8],
    signature_chirho: &GeoEd25519SignatureChirho,
) -> GeoGenesisResultChirho<()> {
    let verifying_key_chirho = curve_point_verifying_key_chirho(expected_key_chirho)?;
    let message_chirho = domain_separated_message_chirho(class_chirho, unsigned_bytes_chirho);
    let signature_chirho = Signature::from_bytes(signature_chirho.as_bytes_chirho());
    verifying_key_chirho
        .verify_strict(&message_chirho, &signature_chirho)
        .map_err(|_error_chirho| GeoGenesisRefusalChirho::SignatureRefusedChirho)
}

/// The operator-private custody trust pins (design section 8): the ruled split profile plus the two
/// distinct dedicated expected public keys. This is the separately custody-verified operator config
/// surface; the pins live here, never in a plan or packet, and no key from an artifact can select a
/// verifier. In production these are loaded from custody-verified config (8.3); this type is the
/// verified in-memory shape the verifier consumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoGenesisTrustPinsChirho {
    profile_chirho: GeoGenesisTrustProfileChirho,
    plan_authority_key_chirho: GeoEd25519PublicKeyChirho,
    acceptance_authority_key_chirho: GeoEd25519PublicKeyChirho,
}

impl GeoGenesisTrustPinsChirho {
    /// Build the ruled split-profile pins. Per the section 8 ruling the two dedicated keys are
    /// DISTINCT and each is a valid curve point; equal or non-curve pins refuse. The profile is fixed
    /// to the ruled `SplitDedicatedPlanAndAcceptanceAuthoritiesChirho` because that is what these two
    /// separate keys represent.
    pub fn new_split_chirho(
        plan_authority_key_chirho: GeoEd25519PublicKeyChirho,
        acceptance_authority_key_chirho: GeoEd25519PublicKeyChirho,
    ) -> GeoGenesisResultChirho<Self> {
        curve_point_verifying_key_chirho(&plan_authority_key_chirho)
            .map_err(|_error_chirho| GeoGenesisRefusalChirho::TrustPinsRefusedChirho)?;
        curve_point_verifying_key_chirho(&acceptance_authority_key_chirho)
            .map_err(|_error_chirho| GeoGenesisRefusalChirho::TrustPinsRefusedChirho)?;
        if plan_authority_key_chirho == acceptance_authority_key_chirho {
            return Err(GeoGenesisRefusalChirho::TrustPinsRefusedChirho);
        }
        Ok(Self {
            profile_chirho:
                GeoGenesisTrustProfileChirho::SplitDedicatedPlanAndAcceptanceAuthoritiesChirho,
            plan_authority_key_chirho,
            acceptance_authority_key_chirho,
        })
    }

    /// The ruled trust profile these pins represent.
    pub fn profile_chirho(&self) -> GeoGenesisTrustProfileChirho {
        self.profile_chirho
    }

    /// The custody-pinned plan-authority verifier key.
    pub fn plan_authority_key_chirho(&self) -> GeoEd25519PublicKeyChirho {
        self.plan_authority_key_chirho
    }

    /// The custody-pinned acceptance-authority verifier key.
    pub fn acceptance_authority_key_chirho(&self) -> GeoEd25519PublicKeyChirho {
        self.acceptance_authority_key_chirho
    }

    /// The expected verifier key for an operator-authority role. Member keys come from the verified
    /// plan topology and the custody authority is its own separately pinned key, so neither has a
    /// pinned key in these plan/acceptance trust pins.
    pub fn expected_authority_key_chirho(
        &self,
        role_chirho: GeoSignerRoleChirho,
    ) -> Option<GeoEd25519PublicKeyChirho> {
        match role_chirho {
            GeoSignerRoleChirho::PlanAuthorityChirho => Some(self.plan_authority_key_chirho),
            GeoSignerRoleChirho::AcceptanceAuthorityChirho => {
                Some(self.acceptance_authority_key_chirho)
            }
            GeoSignerRoleChirho::MemberChirho | GeoSignerRoleChirho::CustodyAuthorityChirho => None,
        }
    }
}

/// A role-bound signer over one pre-provisioned Ed25519 key. It loads an EXISTING key (never
/// generates), verifies the loaded public key equals the custody-supplied expected pin, and signs
/// only message classes its role owns — a plan-authority signer refuses an acceptance-class message
/// by a distinct reason. The private handle is never exposed; only signatures leave.
pub struct GeoRoleSignerChirho {
    role_chirho: GeoSignerRoleChirho,
    signing_key_chirho: SigningKey,
    public_key_chirho: GeoEd25519PublicKeyChirho,
}

impl fmt::Debug for GeoRoleSignerChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("GeoRoleSignerChirho")
            .field("role_chirho", &self.role_chirho)
            .field("public_key_chirho", &self.public_key_chirho)
            .field("key_material_chirho", &"<redacted-chirho>")
            .finish()
    }
}

impl GeoRoleSignerChirho {
    /// Load an EXISTING dedicated key from `key_file_chirho`, bind it to `role_chirho`, and require the
    /// loaded public key to equal the custody-supplied `expected_pin_chirho`. NEVER generates a key;
    /// a missing/non-regular/wrong-length/all-zero key refuses. A loaded key that does not match the
    /// pin refuses with a pin mismatch (the operator provisioned the wrong key). Full key-file custody
    /// (mode/owner/hardlink) is the 8.3 custody checkpoint; here we bound the read and reject symlinks.
    pub fn load_existing_pinned_chirho(
        role_chirho: GeoSignerRoleChirho,
        key_file_chirho: &Path,
        expected_pin_chirho: &GeoEd25519PublicKeyChirho,
    ) -> GeoGenesisResultChirho<Self> {
        let signing_key_chirho = load_existing_signing_key_chirho(key_file_chirho)?;
        let public_bytes_chirho = *signing_key_chirho.verifying_key().as_bytes();
        let public_key_chirho = GeoEd25519PublicKeyChirho::new_chirho(public_bytes_chirho)?;
        if public_key_chirho != *expected_pin_chirho {
            return Err(GeoGenesisRefusalChirho::CustodyPinMismatchChirho);
        }
        Ok(Self {
            role_chirho,
            signing_key_chirho,
            public_key_chirho,
        })
    }

    /// The signer's public key (equal to its custody pin).
    pub fn public_key_chirho(&self) -> GeoEd25519PublicKeyChirho {
        self.public_key_chirho
    }

    /// Sign one domain-separated message of `class_chirho`, refusing any class this signer's role does
    /// not own. This is the cross-role refusal: a plan-authority signer cannot produce an
    /// acceptance-class signature, and vice versa.
    pub(crate) fn sign_class_chirho(
        &self,
        class_chirho: GeoGenesisMessageClassChirho,
        unsigned_bytes_chirho: &[u8],
    ) -> GeoGenesisResultChirho<GeoEd25519SignatureChirho> {
        if class_chirho.owning_role_chirho() != self.role_chirho {
            return Err(
                GeoGenesisRefusalChirho::CrossRoleMessageClassRefusedChirho {
                    signer_role_chirho: self.role_chirho,
                    message_class_chirho: class_chirho,
                },
            );
        }
        let message_chirho = domain_separated_message_chirho(class_chirho, unsigned_bytes_chirho);
        let signature_chirho = self.signing_key_chirho.sign(&message_chirho);
        GeoEd25519SignatureChirho::new_chirho(signature_chirho.to_bytes())
    }
}

/// Read an existing 32-byte Ed25519 seed from a bounded regular file, refusing symlinks, wrong
/// lengths, and the all-zero seed. This function has NO create path: it never generates or writes a
/// key. The seed is held in zeroizing memory and dropped after the key is derived.
fn load_existing_signing_key_chirho(key_file_chirho: &Path) -> GeoGenesisResultChirho<SigningKey> {
    use std::io::Read;

    #[cfg(unix)]
    {
        let symlink_metadata_chirho = std::fs::symlink_metadata(key_file_chirho)
            .map_err(|_error_chirho| GeoGenesisRefusalChirho::ExistingSigningKeyRefusedChirho)?;
        if symlink_metadata_chirho.file_type().is_symlink() {
            return Err(GeoGenesisRefusalChirho::ExistingSigningKeyRefusedChirho);
        }
    }
    let mut file_chirho = std::fs::File::open(key_file_chirho)
        .map_err(|_error_chirho| GeoGenesisRefusalChirho::ExistingSigningKeyRefusedChirho)?;
    let metadata_chirho = file_chirho
        .metadata()
        .map_err(|_error_chirho| GeoGenesisRefusalChirho::ExistingSigningKeyRefusedChirho)?;
    if !metadata_chirho.is_file() || metadata_chirho.len() != 32 {
        return Err(GeoGenesisRefusalChirho::ExistingSigningKeyRefusedChirho);
    }
    let mut seed_chirho = Zeroizing::new([0u8; 32]);
    file_chirho
        .read_exact(seed_chirho.as_mut())
        .map_err(|_error_chirho| GeoGenesisRefusalChirho::ExistingSigningKeyRefusedChirho)?;
    let mut overflow_chirho = [0u8; 1];
    if file_chirho
        .read(&mut overflow_chirho)
        .map_err(|_error_chirho| GeoGenesisRefusalChirho::ExistingSigningKeyRefusedChirho)?
        != 0
    {
        return Err(GeoGenesisRefusalChirho::ExistingSigningKeyRefusedChirho);
    }
    if seed_chirho.iter().all(|byte_chirho| *byte_chirho == 0) {
        return Err(GeoGenesisRefusalChirho::ExistingSigningKeyRefusedChirho);
    }
    Ok(SigningKey::from_bytes(&seed_chirho))
}
