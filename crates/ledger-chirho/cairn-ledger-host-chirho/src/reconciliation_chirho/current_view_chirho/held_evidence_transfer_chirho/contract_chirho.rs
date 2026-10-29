// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::fork_baseline_chirho::{
    load_gd7_fork_baseline_transfer_page_chirho, verify_gd7_fork_baseline_transfer_page_chirho,
};
use super::super::winner_history_chirho::{
    load_gd7_winner_history_transfer_page_chirho, verify_gd7_winner_history_transfer_page_chirho,
};
use super::super::{
    canonical_json_chirho, digest_bytes_chirho, is_lower_hex_digest_chirho,
    validate_identity_chirho, validate_key_and_signature_chirho, Gd7ForkBaselineIdentityChirho,
    Gd7ForkBaselineRefusalChirho, Gd7ForkBaselineRootChirho, Gd7ReconciliationSignerPortChirho,
    Gd7ReconciliationVerifierPortChirho, Gd7WinnerHistoryIdentityChirho,
    Gd7WinnerHistoryRefusalChirho, Gd7WinnerHistoryRootChirho, LedgerStoragePortChirho,
    VerifiedGd7ForkBaselineRootChirho, VerifiedGd7WinnerHistoryRootChirho,
};
use crate::reconciliation_chirho::Gd7ReconciliationIdentityChirho;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

pub const GD7_WINNER_EVIDENCE_PAGE_GRANT_SCHEMA_V1_CHIRHO: &str =
    "gd7-winner-evidence-page-grant-v1-chirho";
pub const GD7_WINNER_EVIDENCE_MANIFEST_SCHEMA_V1_CHIRHO: &str =
    "gd7-winner-evidence-manifest-v1-chirho";
pub const MAX_GD7_WINNER_EVIDENCE_PAGE_GRANT_BYTES_CHIRHO: usize = 8 * 1024;
pub const MAX_GD7_WINNER_EVIDENCE_MANIFEST_BYTES_CHIRHO: usize = 64 * 1024;

/// Exact accepted-handoff coordinate shared by both immutable evidence families.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7HeldEvidenceTransferIdentityChirho {
    pub reconciliation_identity_chirho: Gd7ReconciliationIdentityChirho,
    pub reconciliation_checkpoint_ref_chirho: String,
    pub held_view_transfer_checkpoint_ref_chirho: String,
    pub winner_handoff_attempt_digest_chirho: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7WinnerEvidenceFamilyChirho {
    WinnerHistoryChirho,
    ForkBaselineChirho,
}

/// One recipient-bound authorization for exactly one content-addressed evidence page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerEvidencePageGrantChirho {
    pub schema_chirho: String,
    pub transfer_identity_digest_chirho: String,
    pub family_chirho: Gd7WinnerEvidenceFamilyChirho,
    pub root_object_digest_chirho: String,
    pub page_index_chirho: u64,
    pub page_object_digest_chirho: String,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

/// Winner-signed root pair and first grants for one accepted held recipient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerEvidenceManifestChirho {
    pub schema_chirho: String,
    pub transfer_identity_chirho: Gd7HeldEvidenceTransferIdentityChirho,
    pub winner_history_root_object_digest_chirho: String,
    pub winner_history_root_chirho: Gd7WinnerHistoryRootChirho,
    pub winner_history_first_grant_chirho: Gd7WinnerEvidencePageGrantChirho,
    pub fork_baseline_root_object_digest_chirho: String,
    pub fork_baseline_root_chirho: Gd7ForkBaselineRootChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_baseline_first_grant_chirho: Option<Gd7WinnerEvidencePageGrantChirho>,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

/// Canonical page bytes plus the next recipient-bound grant, if any.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerEvidencePageTransferChirho {
    pub grant_chirho: Gd7WinnerEvidencePageGrantChirho,
    pub canonical_page_bytes_chirho: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_grant_chirho: Option<Gd7WinnerEvidencePageGrantChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7WinnerEvidenceTransferRefusalChirho {
    InvalidIdentityChirho,
    WrongWinnerSignerChirho,
    WrongHeldRecipientChirho,
    InvalidManifestChirho,
    InvalidGrantChirho,
    InvalidPageChirho,
    OversizedManifestChirho,
    OversizedGrantChirho,
    SerializationChirho,
    SigningChirho,
    HistoryChirho(Gd7WinnerHistoryRefusalChirho),
    ForkBaselineChirho(Gd7ForkBaselineRefusalChirho),
}

impl fmt::Display for Gd7WinnerEvidenceTransferRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentityChirho => {
                formatter_chirho.write_str("GD7 held evidence-transfer identity is invalid")
            }
            Self::WrongWinnerSignerChirho => {
                formatter_chirho.write_str("GD7 evidence transfer used the wrong winner signer")
            }
            Self::WrongHeldRecipientChirho => {
                formatter_chirho.write_str("GD7 evidence transfer named the wrong held recipient")
            }
            Self::InvalidManifestChirho => {
                formatter_chirho.write_str("GD7 winner evidence manifest is invalid")
            }
            Self::InvalidGrantChirho => {
                formatter_chirho.write_str("GD7 winner evidence page grant is invalid")
            }
            Self::InvalidPageChirho => {
                formatter_chirho.write_str("GD7 winner evidence page transfer is invalid")
            }
            Self::OversizedManifestChirho => {
                formatter_chirho.write_str("GD7 winner evidence manifest is oversized")
            }
            Self::OversizedGrantChirho => {
                formatter_chirho.write_str("GD7 winner evidence page grant is oversized")
            }
            Self::SerializationChirho => {
                formatter_chirho.write_str("GD7 winner evidence transfer serialization failed")
            }
            Self::SigningChirho => {
                formatter_chirho.write_str("GD7 winner evidence transfer signing failed")
            }
            Self::HistoryChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 winner-history transfer refused: {error_chirho}"
                )
            }
            Self::ForkBaselineChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 fork-baseline transfer refused: {error_chirho}"
                )
            }
        }
    }
}

impl Error for Gd7WinnerEvidenceTransferRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::HistoryChirho(error_chirho) => Some(error_chirho),
            Self::ForkBaselineChirho(error_chirho) => Some(error_chirho),
            _ => None,
        }
    }
}

impl From<Gd7WinnerHistoryRefusalChirho> for Gd7WinnerEvidenceTransferRefusalChirho {
    fn from(error_chirho: Gd7WinnerHistoryRefusalChirho) -> Self {
        Self::HistoryChirho(error_chirho)
    }
}

impl From<Gd7ForkBaselineRefusalChirho> for Gd7WinnerEvidenceTransferRefusalChirho {
    fn from(error_chirho: Gd7ForkBaselineRefusalChirho) -> Self {
        Self::ForkBaselineChirho(error_chirho)
    }
}

pub fn gd7_held_evidence_transfer_identity_digest_chirho(
    identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
) -> Result<String, Gd7WinnerEvidenceTransferRefusalChirho> {
    validate_transfer_identity_chirho(identity_chirho)?;
    canonical_json_chirho(identity_chirho)
        .map(|bytes_chirho| digest_bytes_chirho(&bytes_chirho))
        .map_err(|_| Gd7WinnerEvidenceTransferRefusalChirho::SerializationChirho)
}

pub fn build_gd7_winner_evidence_manifest_chirho(
    transfer_identity_chirho: Gd7HeldEvidenceTransferIdentityChirho,
    winner_history_root_chirho: &VerifiedGd7WinnerHistoryRootChirho,
    fork_baseline_root_chirho: &VerifiedGd7ForkBaselineRootChirho,
    winner_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
) -> Result<Gd7WinnerEvidenceManifestChirho, Gd7WinnerEvidenceTransferRefusalChirho> {
    validate_transfer_identity_chirho(&transfer_identity_chirho)?;
    let winner_node_chirho = &transfer_identity_chirho
        .reconciliation_identity_chirho
        .winner_node_chirho;
    if winner_signer_chirho.key_id_chirho() != *winner_node_chirho {
        return Err(Gd7WinnerEvidenceTransferRefusalChirho::WrongWinnerSignerChirho);
    }
    let history_identity_chirho = expected_history_identity_chirho(&transfer_identity_chirho)?;
    let baseline_identity_chirho = expected_baseline_identity_chirho(&transfer_identity_chirho)?;
    if winner_history_root_chirho.root_chirho().identity_chirho != history_identity_chirho
        || fork_baseline_root_chirho.root_chirho().identity_chirho != baseline_identity_chirho
    {
        return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidManifestChirho);
    }
    let transfer_identity_digest_chirho =
        gd7_held_evidence_transfer_identity_digest_chirho(&transfer_identity_chirho)?;
    let history_root_chirho = winner_history_root_chirho.root_chirho();
    let history_first_index_chirho = history_root_chirho
        .page_count_chirho
        .checked_sub(1)
        .ok_or(Gd7WinnerEvidenceTransferRefusalChirho::InvalidManifestChirho)?;
    let history_first_grant_chirho = sign_grant_chirho(
        Gd7WinnerEvidencePageGrantChirho {
            schema_chirho: GD7_WINNER_EVIDENCE_PAGE_GRANT_SCHEMA_V1_CHIRHO.to_owned(),
            transfer_identity_digest_chirho: transfer_identity_digest_chirho.clone(),
            family_chirho: Gd7WinnerEvidenceFamilyChirho::WinnerHistoryChirho,
            root_object_digest_chirho: winner_history_root_chirho.object_digest_chirho().to_owned(),
            page_index_chirho: history_first_index_chirho,
            page_object_digest_chirho: history_root_chirho.oldest_page_ref_chirho.clone(),
            key_id_chirho: String::new(),
            sig_chirho: String::new(),
        },
        winner_signer_chirho,
    )?;
    let baseline_root_chirho = fork_baseline_root_chirho.root_chirho();
    let baseline_first_grant_chirho = baseline_root_chirho
        .first_page_ref_chirho
        .as_ref()
        .map(|page_ref_chirho| {
            sign_grant_chirho(
                Gd7WinnerEvidencePageGrantChirho {
                    schema_chirho: GD7_WINNER_EVIDENCE_PAGE_GRANT_SCHEMA_V1_CHIRHO.to_owned(),
                    transfer_identity_digest_chirho: transfer_identity_digest_chirho.clone(),
                    family_chirho: Gd7WinnerEvidenceFamilyChirho::ForkBaselineChirho,
                    root_object_digest_chirho: fork_baseline_root_chirho
                        .object_digest_chirho()
                        .to_owned(),
                    page_index_chirho: 0,
                    page_object_digest_chirho: page_ref_chirho.clone(),
                    key_id_chirho: String::new(),
                    sig_chirho: String::new(),
                },
                winner_signer_chirho,
            )
        })
        .transpose()?;
    let mut manifest_chirho = Gd7WinnerEvidenceManifestChirho {
        schema_chirho: GD7_WINNER_EVIDENCE_MANIFEST_SCHEMA_V1_CHIRHO.to_owned(),
        transfer_identity_chirho,
        winner_history_root_object_digest_chirho: winner_history_root_chirho
            .object_digest_chirho()
            .to_owned(),
        winner_history_root_chirho: history_root_chirho.clone(),
        winner_history_first_grant_chirho: history_first_grant_chirho,
        fork_baseline_root_object_digest_chirho: fork_baseline_root_chirho
            .object_digest_chirho()
            .to_owned(),
        fork_baseline_root_chirho: baseline_root_chirho.clone(),
        fork_baseline_first_grant_chirho: baseline_first_grant_chirho,
        key_id_chirho: winner_signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    sign_value_chirho(
        &mut manifest_chirho,
        winner_signer_chirho,
        |manifest_chirho| &mut manifest_chirho.sig_chirho,
    )?;
    verify_gd7_winner_evidence_manifest_chirho(&manifest_chirho, winner_signer_chirho)?;
    Ok(manifest_chirho)
}

pub fn verify_gd7_winner_evidence_manifest_chirho(
    manifest_chirho: &Gd7WinnerEvidenceManifestChirho,
    winner_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<(), Gd7WinnerEvidenceTransferRefusalChirho> {
    validate_transfer_identity_chirho(&manifest_chirho.transfer_identity_chirho)?;
    let winner_node_chirho = &manifest_chirho
        .transfer_identity_chirho
        .reconciliation_identity_chirho
        .winner_node_chirho;
    if winner_verifier_chirho.key_id_chirho() != *winner_node_chirho
        || manifest_chirho.key_id_chirho != *winner_node_chirho
    {
        return Err(Gd7WinnerEvidenceTransferRefusalChirho::WrongWinnerSignerChirho);
    }
    if manifest_chirho.schema_chirho != GD7_WINNER_EVIDENCE_MANIFEST_SCHEMA_V1_CHIRHO {
        return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidManifestChirho);
    }
    verify_signed_value_chirho(
        manifest_chirho,
        &manifest_chirho.sig_chirho,
        winner_verifier_chirho,
        |manifest_chirho| &mut manifest_chirho.sig_chirho,
        MAX_GD7_WINNER_EVIDENCE_MANIFEST_BYTES_CHIRHO,
        Gd7WinnerEvidenceTransferRefusalChirho::OversizedManifestChirho,
        Gd7WinnerEvidenceTransferRefusalChirho::InvalidManifestChirho,
    )?;
    let history_identity_chirho =
        expected_history_identity_chirho(&manifest_chirho.transfer_identity_chirho)?;
    let baseline_identity_chirho =
        expected_baseline_identity_chirho(&manifest_chirho.transfer_identity_chirho)?;
    let history_root_bytes_chirho =
        canonical_json_chirho(&manifest_chirho.winner_history_root_chirho)
            .map_err(|_| Gd7WinnerEvidenceTransferRefusalChirho::SerializationChirho)?;
    let baseline_root_bytes_chirho =
        canonical_json_chirho(&manifest_chirho.fork_baseline_root_chirho)
            .map_err(|_| Gd7WinnerEvidenceTransferRefusalChirho::SerializationChirho)?;
    if manifest_chirho.winner_history_root_chirho.identity_chirho != history_identity_chirho
        || manifest_chirho.fork_baseline_root_chirho.identity_chirho != baseline_identity_chirho
        || digest_bytes_chirho(&history_root_bytes_chirho)
            != manifest_chirho.winner_history_root_object_digest_chirho
        || digest_bytes_chirho(&baseline_root_bytes_chirho)
            != manifest_chirho.fork_baseline_root_object_digest_chirho
    {
        return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidManifestChirho);
    }
    let transfer_identity_digest_chirho = gd7_held_evidence_transfer_identity_digest_chirho(
        &manifest_chirho.transfer_identity_chirho,
    )?;
    verify_grant_chirho(
        &manifest_chirho.winner_history_first_grant_chirho,
        winner_verifier_chirho,
    )?;
    let expected_history_index_chirho = manifest_chirho
        .winner_history_root_chirho
        .page_count_chirho
        .checked_sub(1)
        .ok_or(Gd7WinnerEvidenceTransferRefusalChirho::InvalidManifestChirho)?;
    let history_grant_chirho = &manifest_chirho.winner_history_first_grant_chirho;
    if history_grant_chirho.transfer_identity_digest_chirho != transfer_identity_digest_chirho
        || history_grant_chirho.family_chirho != Gd7WinnerEvidenceFamilyChirho::WinnerHistoryChirho
        || history_grant_chirho.root_object_digest_chirho
            != manifest_chirho.winner_history_root_object_digest_chirho
        || history_grant_chirho.page_index_chirho != expected_history_index_chirho
        || history_grant_chirho.page_object_digest_chirho
            != manifest_chirho
                .winner_history_root_chirho
                .oldest_page_ref_chirho
    {
        return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidManifestChirho);
    }
    match (
        manifest_chirho
            .fork_baseline_root_chirho
            .first_page_ref_chirho
            .as_ref(),
        manifest_chirho.fork_baseline_first_grant_chirho.as_ref(),
    ) {
        (None, None) if manifest_chirho.fork_baseline_root_chirho.page_count_chirho == 0 => {}
        (Some(page_ref_chirho), Some(grant_chirho)) => {
            verify_grant_chirho(grant_chirho, winner_verifier_chirho)?;
            if grant_chirho.transfer_identity_digest_chirho != transfer_identity_digest_chirho
                || grant_chirho.family_chirho != Gd7WinnerEvidenceFamilyChirho::ForkBaselineChirho
                || grant_chirho.root_object_digest_chirho
                    != manifest_chirho.fork_baseline_root_object_digest_chirho
                || grant_chirho.page_index_chirho != 0
                || &grant_chirho.page_object_digest_chirho != page_ref_chirho
            {
                return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidManifestChirho);
            }
        }
        _ => return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidManifestChirho),
    }
    Ok(())
}

pub fn fetch_gd7_winner_evidence_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    manifest_chirho: &Gd7WinnerEvidenceManifestChirho,
    requester_chirho: &str,
    grant_chirho: Gd7WinnerEvidencePageGrantChirho,
    winner_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
) -> Result<Gd7WinnerEvidencePageTransferChirho, Gd7WinnerEvidenceTransferRefusalChirho> {
    verify_gd7_winner_evidence_manifest_chirho(manifest_chirho, winner_signer_chirho)?;
    if requester_chirho
        != manifest_chirho
            .transfer_identity_chirho
            .reconciliation_identity_chirho
            .held_node_chirho
    {
        return Err(Gd7WinnerEvidenceTransferRefusalChirho::WrongHeldRecipientChirho);
    }
    verify_grant_chirho(&grant_chirho, winner_signer_chirho)?;
    let transfer_identity_digest_chirho = gd7_held_evidence_transfer_identity_digest_chirho(
        &manifest_chirho.transfer_identity_chirho,
    )?;
    if grant_chirho.transfer_identity_digest_chirho != transfer_identity_digest_chirho {
        return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidGrantChirho);
    }
    let (canonical_page_bytes_chirho, next_page_ref_chirho) = match grant_chirho.family_chirho {
        Gd7WinnerEvidenceFamilyChirho::WinnerHistoryChirho => {
            if grant_chirho.root_object_digest_chirho
                != manifest_chirho.winner_history_root_object_digest_chirho
            {
                return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidGrantChirho);
            }
            let identity_chirho =
                expected_history_identity_chirho(&manifest_chirho.transfer_identity_chirho)?;
            let page_chirho = load_gd7_winner_history_transfer_page_chirho(
                storage_chirho,
                &grant_chirho.page_object_digest_chirho,
                &identity_chirho,
            )?;
            if page_chirho.page_index_chirho != grant_chirho.page_index_chirho {
                return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidPageChirho);
            }
            (
                page_chirho.canonical_bytes_chirho,
                page_chirho.next_page_ref_chirho,
            )
        }
        Gd7WinnerEvidenceFamilyChirho::ForkBaselineChirho => {
            if grant_chirho.root_object_digest_chirho
                != manifest_chirho.fork_baseline_root_object_digest_chirho
            {
                return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidGrantChirho);
            }
            let identity_chirho =
                expected_baseline_identity_chirho(&manifest_chirho.transfer_identity_chirho)?;
            let page_chirho = load_gd7_fork_baseline_transfer_page_chirho(
                storage_chirho,
                &grant_chirho.page_object_digest_chirho,
                &identity_chirho,
            )?;
            if page_chirho.page_index_chirho != grant_chirho.page_index_chirho {
                return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidPageChirho);
            }
            (
                page_chirho.canonical_bytes_chirho,
                page_chirho.next_page_ref_chirho,
            )
        }
    };
    let next_grant_chirho = next_page_ref_chirho
        .map(|page_ref_chirho| {
            let page_index_chirho = match grant_chirho.family_chirho {
                Gd7WinnerEvidenceFamilyChirho::WinnerHistoryChirho => grant_chirho
                    .page_index_chirho
                    .checked_sub(1)
                    .ok_or(Gd7WinnerEvidenceTransferRefusalChirho::InvalidPageChirho)?,
                Gd7WinnerEvidenceFamilyChirho::ForkBaselineChirho => grant_chirho
                    .page_index_chirho
                    .checked_add(1)
                    .ok_or(Gd7WinnerEvidenceTransferRefusalChirho::InvalidPageChirho)?,
            };
            sign_grant_chirho(
                Gd7WinnerEvidencePageGrantChirho {
                    schema_chirho: GD7_WINNER_EVIDENCE_PAGE_GRANT_SCHEMA_V1_CHIRHO.to_owned(),
                    transfer_identity_digest_chirho: transfer_identity_digest_chirho.clone(),
                    family_chirho: grant_chirho.family_chirho,
                    root_object_digest_chirho: grant_chirho.root_object_digest_chirho.clone(),
                    page_index_chirho,
                    page_object_digest_chirho: page_ref_chirho,
                    key_id_chirho: String::new(),
                    sig_chirho: String::new(),
                },
                winner_signer_chirho,
            )
        })
        .transpose()?;
    Ok(Gd7WinnerEvidencePageTransferChirho {
        grant_chirho,
        canonical_page_bytes_chirho,
        next_grant_chirho,
    })
}

pub fn verify_gd7_winner_evidence_page_transfer_chirho(
    manifest_chirho: &Gd7WinnerEvidenceManifestChirho,
    evidence_page_transfer_chirho: &Gd7WinnerEvidencePageTransferChirho,
    winner_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<(), Gd7WinnerEvidenceTransferRefusalChirho> {
    verify_gd7_winner_evidence_manifest_chirho(manifest_chirho, winner_verifier_chirho)?;
    verify_grant_chirho(
        &evidence_page_transfer_chirho.grant_chirho,
        winner_verifier_chirho,
    )?;
    let grant_chirho = &evidence_page_transfer_chirho.grant_chirho;
    let next_page_ref_chirho = match grant_chirho.family_chirho {
        Gd7WinnerEvidenceFamilyChirho::WinnerHistoryChirho => {
            let identity_chirho =
                expected_history_identity_chirho(&manifest_chirho.transfer_identity_chirho)?;
            let page_chirho = verify_gd7_winner_history_transfer_page_chirho(
                &evidence_page_transfer_chirho.canonical_page_bytes_chirho,
                &grant_chirho.page_object_digest_chirho,
                &identity_chirho,
            )?;
            if page_chirho.page_index_chirho != grant_chirho.page_index_chirho {
                return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidPageChirho);
            }
            page_chirho.next_page_ref_chirho
        }
        Gd7WinnerEvidenceFamilyChirho::ForkBaselineChirho => {
            let identity_chirho =
                expected_baseline_identity_chirho(&manifest_chirho.transfer_identity_chirho)?;
            let page_chirho = verify_gd7_fork_baseline_transfer_page_chirho(
                &evidence_page_transfer_chirho.canonical_page_bytes_chirho,
                &grant_chirho.page_object_digest_chirho,
                &identity_chirho,
            )?;
            if page_chirho.page_index_chirho != grant_chirho.page_index_chirho {
                return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidPageChirho);
            }
            page_chirho.next_page_ref_chirho
        }
    };
    match (
        next_page_ref_chirho,
        evidence_page_transfer_chirho.next_grant_chirho.as_ref(),
    ) {
        (None, None) => Ok(()),
        (Some(expected_page_ref_chirho), Some(next_grant_chirho)) => {
            verify_grant_chirho(next_grant_chirho, winner_verifier_chirho)?;
            let expected_index_chirho = match grant_chirho.family_chirho {
                Gd7WinnerEvidenceFamilyChirho::WinnerHistoryChirho => grant_chirho
                    .page_index_chirho
                    .checked_sub(1)
                    .ok_or(Gd7WinnerEvidenceTransferRefusalChirho::InvalidPageChirho)?,
                Gd7WinnerEvidenceFamilyChirho::ForkBaselineChirho => grant_chirho
                    .page_index_chirho
                    .checked_add(1)
                    .ok_or(Gd7WinnerEvidenceTransferRefusalChirho::InvalidPageChirho)?,
            };
            if next_grant_chirho.transfer_identity_digest_chirho
                != grant_chirho.transfer_identity_digest_chirho
                || next_grant_chirho.family_chirho != grant_chirho.family_chirho
                || next_grant_chirho.root_object_digest_chirho
                    != grant_chirho.root_object_digest_chirho
                || next_grant_chirho.page_index_chirho != expected_index_chirho
                || next_grant_chirho.page_object_digest_chirho != expected_page_ref_chirho
            {
                return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidPageChirho);
            }
            Ok(())
        }
        _ => Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidPageChirho),
    }
}

fn validate_transfer_identity_chirho(
    identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
) -> Result<(), Gd7WinnerEvidenceTransferRefusalChirho> {
    if !validate_identity_chirho(&identity_chirho.reconciliation_identity_chirho)
        || !is_lower_hex_digest_chirho(&identity_chirho.reconciliation_checkpoint_ref_chirho)
        || !is_lower_hex_digest_chirho(&identity_chirho.held_view_transfer_checkpoint_ref_chirho)
        || !is_lower_hex_digest_chirho(&identity_chirho.winner_handoff_attempt_digest_chirho)
    {
        return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidIdentityChirho);
    }
    Ok(())
}

fn expected_history_identity_chirho(
    transfer_identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
) -> Result<Gd7WinnerHistoryIdentityChirho, Gd7WinnerEvidenceTransferRefusalChirho> {
    Gd7WinnerHistoryIdentityChirho::new_chirho(
        transfer_identity_chirho
            .reconciliation_identity_chirho
            .clone(),
        transfer_identity_chirho
            .winner_handoff_attempt_digest_chirho
            .clone(),
    )
    .map_err(Into::into)
}

fn expected_baseline_identity_chirho(
    transfer_identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
) -> Result<Gd7ForkBaselineIdentityChirho, Gd7WinnerEvidenceTransferRefusalChirho> {
    Gd7ForkBaselineIdentityChirho::new_chirho(
        transfer_identity_chirho
            .reconciliation_identity_chirho
            .clone(),
        transfer_identity_chirho
            .winner_handoff_attempt_digest_chirho
            .clone(),
    )
    .map_err(Into::into)
}

fn sign_grant_chirho(
    mut grant_chirho: Gd7WinnerEvidencePageGrantChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
) -> Result<Gd7WinnerEvidencePageGrantChirho, Gd7WinnerEvidenceTransferRefusalChirho> {
    grant_chirho.key_id_chirho = signer_chirho.key_id_chirho();
    sign_value_chirho(&mut grant_chirho, signer_chirho, |grant_chirho| {
        &mut grant_chirho.sig_chirho
    })?;
    verify_grant_chirho(&grant_chirho, signer_chirho)?;
    Ok(grant_chirho)
}

fn verify_grant_chirho(
    grant_chirho: &Gd7WinnerEvidencePageGrantChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<(), Gd7WinnerEvidenceTransferRefusalChirho> {
    if grant_chirho.schema_chirho != GD7_WINNER_EVIDENCE_PAGE_GRANT_SCHEMA_V1_CHIRHO
        || !is_lower_hex_digest_chirho(&grant_chirho.transfer_identity_digest_chirho)
        || !is_lower_hex_digest_chirho(&grant_chirho.root_object_digest_chirho)
        || !is_lower_hex_digest_chirho(&grant_chirho.page_object_digest_chirho)
        || grant_chirho.key_id_chirho != verifier_chirho.key_id_chirho()
        || !validate_key_and_signature_chirho(&grant_chirho.key_id_chirho, &grant_chirho.sig_chirho)
    {
        return Err(Gd7WinnerEvidenceTransferRefusalChirho::InvalidGrantChirho);
    }
    verify_signed_value_chirho(
        grant_chirho,
        &grant_chirho.sig_chirho,
        verifier_chirho,
        |grant_chirho| &mut grant_chirho.sig_chirho,
        MAX_GD7_WINNER_EVIDENCE_PAGE_GRANT_BYTES_CHIRHO,
        Gd7WinnerEvidenceTransferRefusalChirho::OversizedGrantChirho,
        Gd7WinnerEvidenceTransferRefusalChirho::InvalidGrantChirho,
    )
}

fn sign_value_chirho<ValueChirho: Clone + Serialize>(
    value_chirho: &mut ValueChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    signature_chirho: impl Fn(&mut ValueChirho) -> &mut String,
) -> Result<(), Gd7WinnerEvidenceTransferRefusalChirho> {
    signature_chirho(value_chirho).clear();
    let unsigned_bytes_chirho = canonical_json_chirho(value_chirho)
        .map_err(|_| Gd7WinnerEvidenceTransferRefusalChirho::SerializationChirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7WinnerEvidenceTransferRefusalChirho::SerializationChirho)?;
    *signature_chirho(value_chirho) = signer_chirho
        .sign_chirho(unsigned_line_chirho)
        .map_err(|_| Gd7WinnerEvidenceTransferRefusalChirho::SigningChirho)?;
    Ok(())
}

fn verify_signed_value_chirho<ValueChirho: Clone + Serialize>(
    value_chirho: &ValueChirho,
    signature_value_chirho: &str,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    signature_chirho: impl Fn(&mut ValueChirho) -> &mut String,
    maximum_bytes_chirho: usize,
    oversized_chirho: Gd7WinnerEvidenceTransferRefusalChirho,
    invalid_signature_chirho: Gd7WinnerEvidenceTransferRefusalChirho,
) -> Result<(), Gd7WinnerEvidenceTransferRefusalChirho> {
    let canonical_bytes_chirho = canonical_json_chirho(value_chirho)
        .map_err(|_| Gd7WinnerEvidenceTransferRefusalChirho::SerializationChirho)?;
    if canonical_bytes_chirho.len() > maximum_bytes_chirho {
        return Err(oversized_chirho);
    }
    let mut unsigned_chirho = value_chirho.clone();
    signature_chirho(&mut unsigned_chirho).clear();
    let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)
        .map_err(|_| Gd7WinnerEvidenceTransferRefusalChirho::SerializationChirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7WinnerEvidenceTransferRefusalChirho::SerializationChirho)?;
    if !verifier_chirho.verify_chirho(unsigned_line_chirho, signature_value_chirho) {
        return Err(invalid_signature_chirho);
    }
    Ok(())
}
