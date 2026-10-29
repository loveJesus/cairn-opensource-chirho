// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A deliberate, node-signed incarnation for one regenesis activation canary lineage.
//!
//! Plan-derived HLC, epoch, and first-term values can repeat when the same plan is replayed. This
//! anchor instead mints 256 bits from the operating system CSPRNG exactly when a fresh canary store
//! is created. Reopening preserves the signed anchor; recreating the complete store mints a new one.
//! A pre-existing store coordinate always refuses. Automatic cleanup cannot distinguish a crash
//! remnant from retained authority, so it must never choose reuse on the operator's behalf.

use crate::elector_port_chirho::NodeIdChirho;
use crate::shadow_canary_chirho::ShadowCanaryAppendCutChirho;
use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::{consistency_group_digest_chirho, ConsistencyGroupIdChirho};
use cairn_signer_chirho::signer_chirho;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const SHADOW_CANARY_ACTIVATION_ANCHOR_SCHEMA_V1_CHIRHO: &str =
    "writer-elector-shadow-canary-activation-anchor-v1-chirho";
pub const SHADOW_CANARY_ACTIVATION_ANCHOR_DOMAIN_V1_CHIRHO: &str =
    "writer-elector-shadow-canary-activation-anchor-signature-v1-chirho";
pub const SHADOW_CANARY_ACTIVATION_ANCHOR_FILE_CHIRHO: &str = "activation-anchor-chirho.json";
const MAX_SHADOW_CANARY_ACTIVATION_ANCHOR_BYTES_CHIRHO: u64 = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedShadowCanaryActivationAnchorChirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub incarnation_chirho: String,
    pub activation_authorization_digest_chirho: String,
    pub activation_plan_digest_chirho: String,
    /// Corroborating filesystem identity, not the lineage discriminator.
    pub resident_identity_digest_chirho: String,
    pub activation_append_cut_chirho: ShadowCanaryAppendCutChirho,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedShadowCanaryActivationAnchorChirho {
    anchor_chirho: SignedShadowCanaryActivationAnchorChirho,
    digest_chirho: String,
}

impl VerifiedShadowCanaryActivationAnchorChirho {
    pub fn anchor_chirho(&self) -> &SignedShadowCanaryActivationAnchorChirho {
        &self.anchor_chirho
    }

    pub fn digest_chirho(&self) -> &str {
        &self.digest_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowCanaryActivationAnchorInputChirho {
    pub activation_authorization_digest_chirho: String,
    pub activation_plan_digest_chirho: String,
    pub resident_identity_digest_chirho: String,
    pub activation_append_cut_chirho: ShadowCanaryAppendCutChirho,
}

/// Implements the activation-incarnation boundary in
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/cf8-canary-window-loss-sequence-chirho.md`.
pub(crate) fn create_new_shadow_canary_activation_anchor_chirho(
    evidence_root_chirho: &Path,
    sign_root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    node_id_chirho: &NodeIdChirho,
    input_chirho: ShadowCanaryActivationAnchorInputChirho,
) -> Result<VerifiedShadowCanaryActivationAnchorChirho> {
    create_new_shadow_canary_activation_anchor_with_entropy_chirho(
        evidence_root_chirho,
        sign_root_chirho,
        group_chirho,
        node_id_chirho,
        input_chirho,
        |incarnation_bytes_chirho| {
            OsRng
                .try_fill_bytes(incarnation_bytes_chirho)
                .map_err(|_| anyhow::anyhow!("ShadowCanaryActivationAnchorEntropyRefusedChirho"))
        },
    )
}

fn create_new_shadow_canary_activation_anchor_with_entropy_chirho<EntropyChirho>(
    evidence_root_chirho: &Path,
    sign_root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    node_id_chirho: &NodeIdChirho,
    input_chirho: ShadowCanaryActivationAnchorInputChirho,
    entropy_chirho: EntropyChirho,
) -> Result<VerifiedShadowCanaryActivationAnchorChirho>
where
    EntropyChirho: FnOnce(&mut [u8; 32]) -> Result<()>,
{
    require_missing_store_coordinate_chirho(evidence_root_chirho)?;
    let existing_key_chirho = signer_chirho::existing_pubkey_hex_chirho(sign_root_chirho)
        .context("load activation-anchor node signing key")?;
    if existing_key_chirho != node_id_chirho.0 {
        bail!("ShadowCanaryActivationAnchorNodeIdentityRefusedChirho");
    }
    validate_anchor_input_chirho(group_chirho, &input_chirho)?;

    std::fs::create_dir(evidence_root_chirho).map_err(|error_chirho| {
        if error_chirho.kind() == ErrorKind::AlreadyExists {
            anyhow::anyhow!("ShadowCanaryActivationAnchorCollisionRefusedChirho")
        } else {
            anyhow::anyhow!("ShadowCanaryActivationAnchorCreateRefusedChirho")
        }
    })?;
    let mut incarnation_bytes_chirho = [0_u8; 32];
    entropy_chirho(&mut incarnation_bytes_chirho)?;
    let incarnation_chirho = lower_hex_chirho(&incarnation_bytes_chirho);
    let group_digest_chirho = consistency_group_digest_chirho(group_chirho)?;
    let mut anchor_chirho = SignedShadowCanaryActivationAnchorChirho {
        schema_chirho: SHADOW_CANARY_ACTIVATION_ANCHOR_SCHEMA_V1_CHIRHO.to_owned(),
        signature_domain_chirho: SHADOW_CANARY_ACTIVATION_ANCHOR_DOMAIN_V1_CHIRHO.to_owned(),
        node_id_chirho: node_id_chirho.0.clone(),
        consistency_group_digest_chirho: group_digest_chirho,
        incarnation_chirho,
        activation_authorization_digest_chirho: input_chirho.activation_authorization_digest_chirho,
        activation_plan_digest_chirho: input_chirho.activation_plan_digest_chirho,
        resident_identity_digest_chirho: input_chirho.resident_identity_digest_chirho,
        activation_append_cut_chirho: input_chirho.activation_append_cut_chirho,
        key_id_chirho: node_id_chirho.0.clone(),
        sig_chirho: String::new(),
    };
    anchor_chirho.sig_chirho = signer_chirho::sign_message_with_existing_key_chirho(
        sign_root_chirho,
        &unsigned_anchor_message_chirho(&anchor_chirho)?,
    )?;
    validate_anchor_shape_chirho(&anchor_chirho, group_chirho, node_id_chirho)?;
    let bytes_chirho = serde_json::to_vec(&anchor_chirho)?;
    if bytes_chirho.is_empty()
        || u64::try_from(bytes_chirho.len()).ok()
            > Some(MAX_SHADOW_CANARY_ACTIVATION_ANCHOR_BYTES_CHIRHO)
    {
        bail!("ShadowCanaryActivationAnchorBytesRefusedChirho");
    }
    write_private_create_new_chirho(&anchor_path_chirho(evidence_root_chirho), &bytes_chirho)?;
    sync_directory_chirho(evidence_root_chirho)?;
    let parent_chirho = evidence_root_chirho
        .parent()
        .ok_or_else(|| anyhow::anyhow!("ShadowCanaryActivationAnchorParentRefusedChirho"))?;
    sync_directory_chirho(parent_chirho)?;
    load_required_shadow_canary_activation_anchor_chirho(
        evidence_root_chirho,
        sign_root_chirho,
        group_chirho,
        node_id_chirho,
    )
}

pub fn load_optional_shadow_canary_activation_anchor_chirho(
    evidence_root_chirho: &Path,
    sign_root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    node_id_chirho: &NodeIdChirho,
) -> Result<Option<VerifiedShadowCanaryActivationAnchorChirho>> {
    let path_chirho = anchor_path_chirho(evidence_root_chirho);
    match std::fs::symlink_metadata(&path_chirho) {
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => Ok(None),
        Err(error_chirho) => Err(error_chirho).context("inspect activation-anchor coordinate"),
        Ok(_) => load_required_shadow_canary_activation_anchor_chirho(
            evidence_root_chirho,
            sign_root_chirho,
            group_chirho,
            node_id_chirho,
        )
        .map(Some),
    }
}

pub fn load_required_shadow_canary_activation_anchor_chirho(
    evidence_root_chirho: &Path,
    sign_root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    node_id_chirho: &NodeIdChirho,
) -> Result<VerifiedShadowCanaryActivationAnchorChirho> {
    let path_chirho = anchor_path_chirho(evidence_root_chirho);
    let bytes_chirho = read_bounded_regular_file_chirho(&path_chirho)?;
    let anchor_chirho: SignedShadowCanaryActivationAnchorChirho =
        serde_json::from_slice(&bytes_chirho).context("decode shadow canary activation anchor")?;
    validate_anchor_shape_chirho(&anchor_chirho, group_chirho, node_id_chirho)?;
    if signer_chirho::existing_pubkey_hex_chirho(sign_root_chirho)? != node_id_chirho.0 {
        bail!("ShadowCanaryActivationAnchorNodeIdentityRefusedChirho");
    }
    if !signer_chirho::verify_with_pubkey_chirho(
        &node_id_chirho.0,
        &unsigned_anchor_message_chirho(&anchor_chirho)?,
        &anchor_chirho.sig_chirho,
    )? {
        bail!("ShadowCanaryActivationAnchorSignatureRefusedChirho");
    }
    Ok(VerifiedShadowCanaryActivationAnchorChirho {
        digest_chirho: activation_anchor_digest_chirho(&anchor_chirho)?,
        anchor_chirho,
    })
}

pub fn activation_anchor_digest_chirho(
    anchor_chirho: &SignedShadowCanaryActivationAnchorChirho,
) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(anchor_chirho)?)
        .to_hex()
        .to_string())
}

fn validate_anchor_input_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    input_chirho: &ShadowCanaryActivationAnchorInputChirho,
) -> Result<()> {
    if !tagged_digest_has_shape_chirho(&input_chirho.activation_authorization_digest_chirho)
        || !is_lower_hex_chirho(&input_chirho.activation_plan_digest_chirho, 64)
        || !tagged_digest_has_shape_chirho(&input_chirho.resident_identity_digest_chirho)
        || !append_cut_has_shape_chirho(&input_chirho.activation_append_cut_chirho, group_chirho)?
    {
        bail!("ShadowCanaryActivationAnchorInputRefusedChirho");
    }
    Ok(())
}

fn validate_anchor_shape_chirho(
    anchor_chirho: &SignedShadowCanaryActivationAnchorChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    node_id_chirho: &NodeIdChirho,
) -> Result<()> {
    if anchor_chirho.schema_chirho != SHADOW_CANARY_ACTIVATION_ANCHOR_SCHEMA_V1_CHIRHO
        || anchor_chirho.signature_domain_chirho != SHADOW_CANARY_ACTIVATION_ANCHOR_DOMAIN_V1_CHIRHO
        || anchor_chirho.node_id_chirho != node_id_chirho.0
        || anchor_chirho.key_id_chirho != node_id_chirho.0
        || anchor_chirho.consistency_group_digest_chirho
            != consistency_group_digest_chirho(group_chirho)?
        || !is_lower_hex_chirho(&anchor_chirho.incarnation_chirho, 64)
        || !tagged_digest_has_shape_chirho(&anchor_chirho.activation_authorization_digest_chirho)
        || !is_lower_hex_chirho(&anchor_chirho.activation_plan_digest_chirho, 64)
        || !tagged_digest_has_shape_chirho(&anchor_chirho.resident_identity_digest_chirho)
        || !append_cut_has_shape_chirho(&anchor_chirho.activation_append_cut_chirho, group_chirho)?
        || anchor_chirho.sig_chirho.is_empty()
    {
        bail!("ShadowCanaryActivationAnchorShapeRefusedChirho");
    }
    Ok(())
}

fn append_cut_has_shape_chirho(
    cut_chirho: &ShadowCanaryAppendCutChirho,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<bool> {
    Ok(cut_chirho.append_seq_chirho > 0
        && is_lower_hex_chirho(&cut_chirho.append_record_digest_chirho, 64)
        && cut_chirho.append_hlc_physical_ms_chirho > 0
        && cut_chirho.process_generation_chirho > 0
        && cut_chirho.durable_term_chirho > 0
        && cut_chirho.fence_epoch_chirho > 0
        && cut_chirho.fence_group_digest_chirho == consistency_group_digest_chirho(group_chirho)?)
}

fn require_missing_store_coordinate_chirho(evidence_root_chirho: &Path) -> Result<()> {
    match std::fs::symlink_metadata(evidence_root_chirho) {
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => Ok(()),
        _ => bail!("ShadowCanaryActivationAnchorCollisionRefusedChirho"),
    }
}

fn write_private_create_new_chirho(path_chirho: &Path, bytes_chirho: &[u8]) -> Result<()> {
    let mut options_chirho = OpenOptions::new();
    options_chirho.write(true).create_new(true).mode(0o600);
    let mut file_chirho = options_chirho
        .open(path_chirho)
        .map_err(|_| anyhow::anyhow!("ShadowCanaryActivationAnchorCollisionRefusedChirho"))?;
    file_chirho
        .write_all(bytes_chirho)
        .context("write shadow canary activation anchor")?;
    file_chirho
        .sync_all()
        .context("sync shadow canary activation anchor")
}

fn read_bounded_regular_file_chirho(path_chirho: &Path) -> Result<Vec<u8>> {
    let path_metadata_chirho = std::fs::symlink_metadata(path_chirho)
        .context("inspect shadow canary activation anchor")?;
    if !path_metadata_chirho.file_type().is_file()
        || path_metadata_chirho.len() == 0
        || path_metadata_chirho.len() > MAX_SHADOW_CANARY_ACTIVATION_ANCHOR_BYTES_CHIRHO
    {
        bail!("ShadowCanaryActivationAnchorBytesRefusedChirho");
    }
    let file_chirho =
        std::fs::File::open(path_chirho).context("open shadow canary activation anchor")?;
    let opened_metadata_chirho = file_chirho
        .metadata()
        .context("inspect opened shadow canary activation anchor")?;
    if !opened_metadata_chirho.is_file()
        || opened_metadata_chirho.len() != path_metadata_chirho.len()
        || opened_metadata_chirho.dev() != path_metadata_chirho.dev()
        || opened_metadata_chirho.ino() != path_metadata_chirho.ino()
    {
        bail!("ShadowCanaryActivationAnchorBytesRefusedChirho");
    }
    let mut bytes_chirho = Vec::with_capacity(opened_metadata_chirho.len() as usize);
    file_chirho
        .take(MAX_SHADOW_CANARY_ACTIVATION_ANCHOR_BYTES_CHIRHO + 1)
        .read_to_end(&mut bytes_chirho)
        .context("read shadow canary activation anchor")?;
    let final_metadata_chirho = std::fs::symlink_metadata(path_chirho)
        .context("reinspect shadow canary activation anchor")?;
    if bytes_chirho.len() as u64 != opened_metadata_chirho.len()
        || !final_metadata_chirho.file_type().is_file()
        || final_metadata_chirho.len() != opened_metadata_chirho.len()
        || final_metadata_chirho.dev() != opened_metadata_chirho.dev()
        || final_metadata_chirho.ino() != opened_metadata_chirho.ino()
    {
        bail!("ShadowCanaryActivationAnchorBytesRefusedChirho");
    }
    Ok(bytes_chirho)
}

fn sync_directory_chirho(path_chirho: &Path) -> Result<()> {
    std::fs::File::open(path_chirho)
        .context("open activation-anchor directory for sync")?
        .sync_all()
        .context("sync activation-anchor directory")
}

fn anchor_path_chirho(evidence_root_chirho: &Path) -> PathBuf {
    evidence_root_chirho.join(SHADOW_CANARY_ACTIVATION_ANCHOR_FILE_CHIRHO)
}

fn unsigned_anchor_message_chirho(
    anchor_chirho: &SignedShadowCanaryActivationAnchorChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = anchor_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

fn lower_hex_chirho(bytes_chirho: &[u8]) -> String {
    let mut value_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        use std::fmt::Write as _;
        let _ = write!(value_chirho, "{byte_chirho:02x}");
    }
    value_chirho
}

fn tagged_digest_has_shape_chirho(value_chirho: &str) -> bool {
    value_chirho
        .rsplit_once(':')
        .is_some_and(|(prefix_chirho, digest_chirho)| {
            !prefix_chirho.is_empty()
                && prefix_chirho.len() <= 160
                && is_lower_hex_chirho(digest_chirho, 64)
        })
}

fn is_lower_hex_chirho(value_chirho: &str, len_chirho: usize) -> bool {
    value_chirho.len() == len_chirho
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

#[cfg(test)]
pub(crate) fn create_new_shadow_canary_activation_anchor_with_fixed_entropy_chirho(
    evidence_root_chirho: &Path,
    sign_root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    node_id_chirho: &NodeIdChirho,
    input_chirho: ShadowCanaryActivationAnchorInputChirho,
    fixed_incarnation_chirho: &[u8],
) -> Result<VerifiedShadowCanaryActivationAnchorChirho> {
    let fixed_incarnation_chirho: [u8; 32] = fixed_incarnation_chirho
        .try_into()
        .map_err(|_| anyhow::anyhow!("ShadowCanaryActivationAnchorEntropyRefusedChirho"))?;
    create_new_shadow_canary_activation_anchor_with_entropy_chirho(
        evidence_root_chirho,
        sign_root_chirho,
        group_chirho,
        node_id_chirho,
        input_chirho,
        |incarnation_bytes_chirho| {
            *incarnation_bytes_chirho = fixed_incarnation_chirho;
            Ok(())
        },
    )
}
