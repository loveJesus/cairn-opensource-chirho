// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The control-plane role signer, its pin-only verifier, and the per-root law that says which key a
//! control-plane record must carry, chosen by a pure function with no I/O.
//!
//! On a geo tenant, control-plane records (apps, routes, policies, identities and their verification
//! closure) are signed by one role key per lineage that the placement's voters hold, so a copied record
//! verifies on any voter. Off geo, records keep the root's own node key. This module never touches a
//! root: the role key arrives as seed bytes the composition resolved from its secret store, and the root
//! evidence arrives already read, so every rule here is armed without a filesystem.
//!
//! Design: `spec-chirho/workstream-state-chirho/c2-durability-chirho/brick1-control-plane-signer-design-chirho.md`
//! (C2.1 brick 1, after `control-plane-signer-decision-chirho.md`).

use crate::signer_chirho::{hex_decode_chirho, hex_encode_chirho};
use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fmt;
use zeroize::Zeroizing;

/// The fixed first field of every control-plane signing domain.
pub const CONTROL_PLANE_DOMAIN_CHIRHO: &str = "cairn-control-plane-v1";

/// The longest tenant id or genesis instance id a lineage accepts, in bytes.
pub const CONTROL_PLANE_LINEAGE_FIELD_MAX_BYTES_CHIRHO: usize = 256;

/// The signing role. There is one today; it is still bound into the domain so a future role cannot replay
/// a control-plane signature as its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlPlaneRoleChirho {
    ControlPlaneChirho,
}

impl ControlPlaneRoleChirho {
    pub fn label_chirho(self) -> &'static str {
        match self {
            Self::ControlPlaneChirho => "control-plane",
        }
    }
}

/// The record families the decision makes portable: its primary families, then their verification
/// closure. Each is bound into the signing domain by a fixed label, so a signature over one family's
/// bytes never verifies as another's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ControlPlaneFamilyChirho {
    AppRecordsChirho,
    AppRouteRecordsChirho,
    AppInputPolicyRecordsChirho,
    AppResponsePolicyRecordsChirho,
    AppRouteResponsePolicyRecordsChirho,
    AppParamsRecordsChirho,
    AppStaticAssetRecordsChirho,
    DomainBindingsChirho,
    PriceBookChirho,
    IdentitiesChirho,
    HeadTransitionReceiptsChirho,
    HeadRemovalsChirho,
    IdentityRevocationsChirho,
    OauthClientsChirho,
    ClientOwnerBindingsChirho,
    AppOwnersChirho,
    ReviewRecordsChirho,
}

impl ControlPlaneFamilyChirho {
    /// Every family, in declaration order.
    pub const ALL_CHIRHO: [Self; 17] = [
        Self::AppRecordsChirho,
        Self::AppRouteRecordsChirho,
        Self::AppInputPolicyRecordsChirho,
        Self::AppResponsePolicyRecordsChirho,
        Self::AppRouteResponsePolicyRecordsChirho,
        Self::AppParamsRecordsChirho,
        Self::AppStaticAssetRecordsChirho,
        Self::DomainBindingsChirho,
        Self::PriceBookChirho,
        Self::IdentitiesChirho,
        Self::HeadTransitionReceiptsChirho,
        Self::HeadRemovalsChirho,
        Self::IdentityRevocationsChirho,
        Self::OauthClientsChirho,
        Self::ClientOwnerBindingsChirho,
        Self::AppOwnersChirho,
        Self::ReviewRecordsChirho,
    ];

    pub fn label_chirho(self) -> &'static str {
        match self {
            Self::AppRecordsChirho => "app-records",
            Self::AppRouteRecordsChirho => "app-route-records",
            Self::AppInputPolicyRecordsChirho => "app-input-policy-records",
            Self::AppResponsePolicyRecordsChirho => "app-response-policy-records",
            Self::AppRouteResponsePolicyRecordsChirho => "app-route-response-policy-records",
            Self::AppParamsRecordsChirho => "app-params-records",
            Self::AppStaticAssetRecordsChirho => "app-static-asset-records",
            Self::DomainBindingsChirho => "domain-bindings",
            Self::PriceBookChirho => "price-book",
            Self::IdentitiesChirho => "identities",
            Self::HeadTransitionReceiptsChirho => "head-transition-receipts",
            Self::HeadRemovalsChirho => "head-removals",
            Self::IdentityRevocationsChirho => "identity-revocations",
            Self::OauthClientsChirho => "oauth-clients",
            Self::ClientOwnerBindingsChirho => "client-owner-bindings",
            Self::AppOwnersChirho => "app-owners",
            Self::ReviewRecordsChirho => "review-records",
        }
    }
}

/// The tenant lineage a role key signs for: the tenant id and the geo genesis instance id. It comes from
/// reviewed config, never from the root. Both fields are non-empty, bounded and free of NUL, the domain
/// separator, so the signing domain parses one way only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlPlaneLineageChirho {
    tenant_id_chirho: String,
    genesis_instance_id_chirho: String,
}

impl ControlPlaneLineageChirho {
    pub fn new_chirho(tenant_id_chirho: &str, genesis_instance_id_chirho: &str) -> Result<Self> {
        validate_lineage_field_chirho("tenant id", tenant_id_chirho)?;
        validate_lineage_field_chirho("genesis instance id", genesis_instance_id_chirho)?;
        Ok(Self {
            tenant_id_chirho: tenant_id_chirho.to_string(),
            genesis_instance_id_chirho: genesis_instance_id_chirho.to_string(),
        })
    }

    pub fn tenant_id_chirho(&self) -> &str {
        &self.tenant_id_chirho
    }

    pub fn genesis_instance_id_chirho(&self) -> &str {
        &self.genesis_instance_id_chirho
    }
}

fn validate_lineage_field_chirho(label_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.is_empty() {
        bail!("ControlPlaneLineageFieldEmptyChirho: {label_chirho}");
    }
    if value_chirho.len() > CONTROL_PLANE_LINEAGE_FIELD_MAX_BYTES_CHIRHO {
        bail!("ControlPlaneLineageFieldTooLongChirho: {label_chirho}");
    }
    if value_chirho.bytes().any(|byte_chirho| byte_chirho == 0) {
        bail!("ControlPlaneLineageFieldNulChirho: {label_chirho}");
    }
    Ok(())
}

/// The exact bytes a control-plane signature covers:
/// `domain \0 role \0 family \0 tenant \0 instance \0 inner`.
///
/// Every field before `inner` is NUL-free (fixed labels, and a validated lineage), so the encoding is
/// injective even though `inner` may hold any bytes.
pub fn control_plane_message_chirho(
    role_chirho: ControlPlaneRoleChirho,
    family_chirho: ControlPlaneFamilyChirho,
    lineage_chirho: &ControlPlaneLineageChirho,
    inner_chirho: &[u8],
) -> Vec<u8> {
    let fields_chirho = [
        CONTROL_PLANE_DOMAIN_CHIRHO,
        role_chirho.label_chirho(),
        family_chirho.label_chirho(),
        lineage_chirho.tenant_id_chirho(),
        lineage_chirho.genesis_instance_id_chirho(),
    ];
    let prefix_len_chirho: usize = fields_chirho
        .iter()
        .map(|field_chirho| field_chirho.len() + 1)
        .sum();
    let mut message_chirho = Vec::with_capacity(prefix_len_chirho + inner_chirho.len());
    for field_chirho in fields_chirho {
        message_chirho.extend_from_slice(field_chirho.as_bytes());
        message_chirho.push(0);
    }
    message_chirho.extend_from_slice(inner_chirho);
    message_chirho
}

/// The public pin of a lineage's role key, from reviewed config: exactly 64 lowercase hex characters
/// naming a valid, non-weak Ed25519 point.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ControlPlanePinChirho {
    key_chirho: VerifyingKey,
}

impl ControlPlanePinChirho {
    pub fn from_hex_chirho(hex_chirho: &str) -> Result<Self> {
        let canonical_chirho = hex_chirho.len() == 64
            && hex_chirho
                .bytes()
                .all(|byte_chirho| matches!(byte_chirho, b'0'..=b'9' | b'a'..=b'f'));
        if !canonical_chirho {
            bail!("ControlPlanePinNotCanonicalHexChirho");
        }
        let bytes_chirho: [u8; 32] = hex_decode_chirho(hex_chirho)?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("ControlPlanePinNotCanonicalHexChirho"))?;
        let key_chirho = VerifyingKey::from_bytes(&bytes_chirho)
            .map_err(|_| anyhow!("ControlPlanePinInvalidPointChirho"))?;
        if key_chirho.is_weak() {
            bail!("ControlPlanePinWeakKeyChirho");
        }
        Ok(Self { key_chirho })
    }

    /// The pin as a key id: its lowercase hex.
    pub fn key_id_hex_chirho(&self) -> String {
        hex_encode_chirho(self.key_chirho.as_bytes())
    }

    pub fn key_bytes_chirho(&self) -> [u8; 32] {
        *self.key_chirho.as_bytes()
    }
}

impl fmt::Debug for ControlPlanePinChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("ControlPlanePinChirho")
            .field("key_id_chirho", &self.key_id_hex_chirho())
            .finish()
    }
}

/// Checks a control-plane signature against the pin alone. It holds no secret and touches no file, so a
/// verification can never mint or move a key (decision rule 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlPlaneVerifierChirho {
    pin_chirho: ControlPlanePinChirho,
    lineage_chirho: ControlPlaneLineageChirho,
}

impl ControlPlaneVerifierChirho {
    pub fn new_chirho(
        pin_chirho: ControlPlanePinChirho,
        lineage_chirho: ControlPlaneLineageChirho,
    ) -> Self {
        Self {
            pin_chirho,
            lineage_chirho,
        }
    }

    pub fn pin_chirho(&self) -> &ControlPlanePinChirho {
        &self.pin_chirho
    }

    pub fn lineage_chirho(&self) -> &ControlPlaneLineageChirho {
        &self.lineage_chirho
    }

    /// `Ok(true)` only for a strict signature by the pin over this family's domain-bound `inner`.
    /// `Ok(false)` for a well-formed signature that does not verify; `Err` for a malformed encoding.
    pub fn verify_chirho(
        &self,
        family_chirho: ControlPlaneFamilyChirho,
        inner_chirho: &[u8],
        sig_hex_chirho: &str,
    ) -> Result<bool> {
        let sig_bytes_chirho = hex_decode_chirho(sig_hex_chirho)?;
        let sig_arr_chirho: [u8; 64] = sig_bytes_chirho
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("ControlPlaneSignatureLengthChirho"))?;
        let message_chirho = control_plane_message_chirho(
            ControlPlaneRoleChirho::ControlPlaneChirho,
            family_chirho,
            &self.lineage_chirho,
            inner_chirho,
        );
        Ok(self
            .pin_chirho
            .key_chirho
            .verify_strict(&message_chirho, &Signature::from_bytes(&sig_arr_chirho))
            .is_ok())
    }
}

/// The role key itself, loaded on a voter. It is built from seed bytes the composition resolved; it
/// refuses an all-zero seed and any seed whose key is not the pin.
pub struct ControlPlaneSignerChirho {
    key_chirho: SigningKey,
    verifier_chirho: ControlPlaneVerifierChirho,
}

impl ControlPlaneSignerChirho {
    pub fn from_seed_chirho(
        seed_chirho: Zeroizing<[u8; 32]>,
        verifier_chirho: ControlPlaneVerifierChirho,
    ) -> Result<Self> {
        if seed_chirho.iter().all(|byte_chirho| *byte_chirho == 0) {
            bail!("ControlPlaneSignerSeedAllZeroChirho");
        }
        let key_chirho = SigningKey::from_bytes(&seed_chirho);
        if key_chirho.verifying_key() != verifier_chirho.pin_chirho.key_chirho {
            bail!("ControlPlaneSignerPinMismatchChirho");
        }
        Ok(Self {
            key_chirho,
            verifier_chirho,
        })
    }

    pub fn verifier_chirho(&self) -> &ControlPlaneVerifierChirho {
        &self.verifier_chirho
    }

    /// A hex signature over this family's domain-bound `inner`.
    pub fn sign_chirho(
        &self,
        family_chirho: ControlPlaneFamilyChirho,
        inner_chirho: &[u8],
    ) -> String {
        let message_chirho = control_plane_message_chirho(
            ControlPlaneRoleChirho::ControlPlaneChirho,
            family_chirho,
            self.verifier_chirho.lineage_chirho(),
            inner_chirho,
        );
        hex_encode_chirho(&self.key_chirho.sign(&message_chirho).to_bytes())
    }
}

impl fmt::Debug for ControlPlaneSignerChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("ControlPlaneSignerChirho")
            .field("verifier_chirho", &self.verifier_chirho)
            .field("key_material_chirho", &"<redacted-chirho>")
            .finish()
    }
}

/// Another role's identity, for the pairwise separation check (decision rule 1): its label, and its
/// secret name and key when known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlPlaneSeparationPeerChirho {
    pub label_chirho: String,
    pub secret_name_chirho: Option<String>,
    pub key_chirho: Option<[u8; 32]>,
}

/// Refuse when the control-plane role shares a secret name or a key with any other role. The caller
/// supplies the six host-ledger signer roles, the GD7 control keys and the node's own key on a voter,
/// or the other pinned verifiers, the GD7 control keys and the node key off the voter set.
pub fn refuse_control_plane_role_collisions_chirho(
    pin_chirho: &ControlPlanePinChirho,
    own_secret_name_chirho: Option<&str>,
    peers_chirho: &[ControlPlaneSeparationPeerChirho],
) -> Result<()> {
    let own_key_chirho = pin_chirho.key_bytes_chirho();
    for peer_chirho in peers_chirho {
        if let (Some(own_name_chirho), Some(peer_name_chirho)) = (
            own_secret_name_chirho,
            peer_chirho.secret_name_chirho.as_deref(),
        ) {
            if own_name_chirho == peer_name_chirho {
                bail!(
                    "ControlPlaneRoleSecretNameCollisionChirho: {}",
                    peer_chirho.label_chirho
                );
            }
        }
        if peer_chirho.key_chirho == Some(own_key_chirho) {
            bail!(
                "ControlPlaneRoleKeyCollisionChirho: {}",
                peer_chirho.label_chirho
            );
        }
    }
    Ok(())
}

/// What a root's law marker (`control-plane-law-chirho.json`) says, once read and parsed by the caller:
/// the pin's key id and the lineage it was written for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlPlaneLawMarkerChirho {
    pub key_id_hex_chirho: String,
    pub lineage_chirho: ControlPlaneLineageChirho,
}

impl ControlPlaneLawMarkerChirho {
    /// The marker a root under this verifier's law carries.
    pub fn for_verifier_chirho(verifier_chirho: &ControlPlaneVerifierChirho) -> Self {
        Self {
            key_id_hex_chirho: verifier_chirho.pin_chirho().key_id_hex_chirho(),
            lineage_chirho: verifier_chirho.lineage_chirho().clone(),
        }
    }
}

/// The reviewed config's control-plane fields. The pin and the lineage arrive together or not at all,
/// and a signer, when present, must be for exactly this pin and lineage.
#[derive(Debug)]
pub struct ControlPlaneConfigChirho {
    verifier_chirho: ControlPlaneVerifierChirho,
    signer_chirho: Option<ControlPlaneSignerChirho>,
}

impl ControlPlaneConfigChirho {
    pub fn new_chirho(
        verifier_chirho: ControlPlaneVerifierChirho,
        signer_chirho: Option<ControlPlaneSignerChirho>,
    ) -> Result<Self, ControlPlaneLawRefusalChirho> {
        if let Some(signer_chirho) = &signer_chirho {
            if signer_chirho.verifier_chirho() != &verifier_chirho {
                return Err(ControlPlaneLawRefusalChirho::SignerNotForConfigChirho);
            }
        }
        Ok(Self {
            verifier_chirho,
            signer_chirho,
        })
    }
}

/// The root's geo evidence, already read by the caller. Each probe treats only a not-found result as
/// absent; any other read failure refuses before selection is ever called.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlPlaneEvidenceChirho {
    /// E1: the persisted writer-authority era is Elected.
    pub era_elected_chirho: bool,
    /// E2: the geo genesis marker directory exists.
    pub genesis_marker_present_chirho: bool,
    /// E3: the root's law marker, when present.
    pub law_marker_chirho: Option<ControlPlaneLawMarkerChirho>,
}

/// Which key a control-plane record on this root must carry.
#[derive(Debug)]
pub enum ControlPlaneLawChirho {
    /// Not a geo root: records keep the root's own node key, as before.
    NodeKeyChirho,
    /// A geo root: records carry the lineage role key, checked against the pin. Boxed, because the key
    /// material dwarfs the node-key case.
    LineageRoleChirho(Box<ControlPlaneLineageLawChirho>),
}

/// A geo root's law, inside [`ControlPlaneLawChirho::LineageRoleChirho`].
#[derive(Debug)]
pub struct ControlPlaneLineageLawChirho {
    pub verifier_chirho: ControlPlaneVerifierChirho,
    /// Present only on a voter; a verifier-only law cannot sign.
    pub signer_chirho: Option<ControlPlaneSignerChirho>,
    /// Whether the root already carries its law marker. When false, the first lineage signing must write
    /// it, create-new and durably, before the record it signs.
    pub law_marker_present_chirho: bool,
}

impl ControlPlaneLawChirho {
    /// Whether a law the caller already holds still stands on the root's evidence, read again. It is the
    /// selector's own table applied to a held law, so a root handle bound earlier refuses once the root
    /// changes under it (C2.1 brick 1b-1a). The node-key law stands only while the root shows no geo
    /// evidence at all. The lineage law stands while its marker is absent or names its own pin and lineage.
    pub fn check_evidence_chirho(
        &self,
        evidence_chirho: &ControlPlaneEvidenceChirho,
    ) -> Result<(), ControlPlaneLawRefusalChirho> {
        match self {
            Self::NodeKeyChirho => {
                if evidence_chirho.law_marker_chirho.is_some()
                    || evidence_chirho.era_elected_chirho
                    || evidence_chirho.genesis_marker_present_chirho
                {
                    Err(ControlPlaneLawRefusalChirho::PinMissingOnGeoRootChirho)
                } else {
                    Ok(())
                }
            }
            Self::LineageRoleChirho(lineage_law_chirho) => match &evidence_chirho.law_marker_chirho
            {
                None => Ok(()),
                Some(marker_chirho)
                    if *marker_chirho
                        == ControlPlaneLawMarkerChirho::for_verifier_chirho(
                            &lineage_law_chirho.verifier_chirho,
                        ) =>
                {
                    Ok(())
                }
                Some(_) => Err(ControlPlaneLawRefusalChirho::MarkerMismatchChirho),
            },
        }
    }

    /// Sign under the lineage law. A node-key law refuses (the caller uses the node signer), and so does a
    /// verifier-only law.
    pub fn sign_lineage_chirho(
        &self,
        family_chirho: ControlPlaneFamilyChirho,
        inner_chirho: &[u8],
    ) -> Result<String> {
        match self {
            Self::NodeKeyChirho => bail!("ControlPlaneLawIsNodeKeyChirho"),
            Self::LineageRoleChirho(lineage_law_chirho) => {
                match &lineage_law_chirho.signer_chirho {
                    Some(signer_chirho) => {
                        Ok(signer_chirho.sign_chirho(family_chirho, inner_chirho))
                    }
                    None => bail!("ControlPlaneSignerUnavailableChirho"),
                }
            }
        }
    }
}

/// Why no law could be chosen. A refusal blocks every control-plane signature and verification on the
/// root until the config or the root is put right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlPlaneLawRefusalChirho {
    /// The root's law marker names a different pin or lineage than the config.
    MarkerMismatchChirho,
    /// The root shows geo evidence, but the config carries no control-plane pin.
    PinMissingOnGeoRootChirho,
    /// The configured signer is not for the configured pin and lineage.
    SignerNotForConfigChirho,
}

impl fmt::Display for ControlPlaneLawRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::MarkerMismatchChirho => "ControlPlaneLawMarkerMismatchChirho",
            Self::PinMissingOnGeoRootChirho => "ControlPlaneLawPinMissingOnGeoRootChirho",
            Self::SignerNotForConfigChirho => "ControlPlaneLawSignerNotForConfigChirho",
        })
    }
}

impl std::error::Error for ControlPlaneLawRefusalChirho {}

/// Choose the law, config first. Root evidence can only force a refusal; it never selects the node key.
///
/// | config | law marker | era Elected or genesis marker | law |
/// |---|---|---|---|
/// | present | absent | any | lineage, marker to be written at the first signing |
/// | present | equal to the config | any | lineage |
/// | present | different | any | refuse: marker mismatch |
/// | absent | present | any | refuse: pin missing on a geo root |
/// | absent | absent | either | refuse: pin missing on a geo root |
/// | absent | absent | neither | node key |
pub fn select_control_plane_law_chirho(
    config_chirho: Option<ControlPlaneConfigChirho>,
    evidence_chirho: &ControlPlaneEvidenceChirho,
) -> Result<ControlPlaneLawChirho, ControlPlaneLawRefusalChirho> {
    match config_chirho {
        Some(config_chirho) => {
            let law_marker_present_chirho = match &evidence_chirho.law_marker_chirho {
                None => false,
                Some(marker_chirho)
                    if *marker_chirho
                        == ControlPlaneLawMarkerChirho::for_verifier_chirho(
                            &config_chirho.verifier_chirho,
                        ) =>
                {
                    true
                }
                Some(_) => return Err(ControlPlaneLawRefusalChirho::MarkerMismatchChirho),
            };
            Ok(ControlPlaneLawChirho::LineageRoleChirho(Box::new(
                ControlPlaneLineageLawChirho {
                    verifier_chirho: config_chirho.verifier_chirho,
                    signer_chirho: config_chirho.signer_chirho,
                    law_marker_present_chirho,
                },
            )))
        }
        None => {
            if evidence_chirho.law_marker_chirho.is_some()
                || evidence_chirho.era_elected_chirho
                || evidence_chirho.genesis_marker_present_chirho
            {
                Err(ControlPlaneLawRefusalChirho::PinMissingOnGeoRootChirho)
            } else {
                Ok(ControlPlaneLawChirho::NodeKeyChirho)
            }
        }
    }
}

#[cfg(test)]
#[path = "control_plane_signer_tests_chirho.rs"]
mod control_plane_signer_tests_chirho;
