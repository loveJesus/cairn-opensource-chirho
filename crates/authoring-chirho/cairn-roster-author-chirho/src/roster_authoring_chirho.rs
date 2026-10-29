// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Offline operator authoring for one complete signed membership-roster bundle.
//!
//! The output is a fresh private directory containing the mixed membership/network/preferred-leader
//! JSONL plus its signed length witness. The command consumes only explicit public coordinates and an
//! already-provisioned local operator keypair. It never creates a key, replaces an existing bundle, or
//! emits private key material.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/serve-write-forwarding-design-chirho.md`.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use cairn_replication_chirho::membership_chirho::{
    roster_prefix_digest_chirho, unsigned_membership_roster_head_message_chirho,
    unsigned_membership_roster_message_chirho, unsigned_node_network_record_message_chirho,
    unsigned_preferred_leader_record_message_chirho, verify_membership_roster_with_head_chirho,
    verify_node_network_records_chirho, verify_preferred_leader_records_chirho,
    MembershipActionChirho, MembershipRosterHeadChirho, MembershipRosterRecordChirho,
    NodeNetworkRecordChirho, PreferredLeaderRecordChirho, MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO,
    MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO, NODE_NETWORK_RECORD_SCHEMA_CHIRHO,
    PREFERRED_LEADER_RECORD_SCHEMA_CHIRHO,
};
use cairn_roster_config_chirho::{derive_elector_config_chirho, derive_preferred_leader_chirho};
use cairn_signer_chirho::signer_chirho::{
    existing_keypair_pubkey_hex_chirho, sign_with_existing_key_possession_chirho,
    verify_with_pubkey_chirho,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const ROSTER_AUTHORING_INPUT_SCHEMA_CHIRHO: &str =
    "membership-roster-authoring-input-v1-chirho";
pub const ROSTER_AUTHORING_REPORT_SCHEMA_CHIRHO: &str =
    "membership-roster-authoring-report-v1-chirho";
pub const ROSTER_OUTPUT_FILE_CHIRHO: &str = "membership-roster-chirho.jsonl";
pub const ROSTER_HEAD_OUTPUT_FILE_CHIRHO: &str = "membership-roster-head-chirho.json";

const MAX_AUTHORING_INPUT_BYTES_CHIRHO: u64 = 64 * 1024;
const MAX_ROSTER_MEMBERS_CHIRHO: usize = 64;
const MAX_LABEL_BYTES_CHIRHO: usize = 128;
const ED25519_PUBLIC_KEY_HEX_BYTES_CHIRHO: usize = 64;
const ED25519_SIGNATURE_HEX_BYTES_CHIRHO: usize = 128;
const WIREGUARD_PUBLIC_KEY_BYTES_CHIRHO: usize = 32;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RosterAuthoringInputChirho {
    pub schema_chirho: String,
    pub at_ms_chirho: u64,
    pub members_chirho: Vec<RosterAuthoringMemberChirho>,
    #[serde(default)]
    pub preferred_leaders_chirho: Vec<RosterAuthoringPreferredLeaderChirho>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RosterAuthoringMemberChirho {
    pub node_pubkey_hex_chirho: String,
    pub region_label_chirho: String,
    pub raft_id_chirho: u64,
    pub wg_pubkey_chirho: String,
    pub mesh_ip_chirho: String,
    pub endpoint_chirho: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RosterAuthoringPreferredLeaderChirho {
    pub group_id_chirho: String,
    pub preferred_leader_raft_id_chirho: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RosterAuthoringReportChirho {
    pub schema_chirho: &'static str,
    pub operator_key_id_chirho: String,
    pub member_count_chirho: usize,
    pub preferred_leader_count_chirho: usize,
    pub roster_record_count_chirho: usize,
    pub roster_blake3_chirho: String,
    pub roster_head_blake3_chirho: String,
    pub roster_file_chirho: PathBuf,
    pub roster_head_file_chirho: PathBuf,
}

struct FreshBundleGuardChirho {
    path_chirho: PathBuf,
    committed_chirho: bool,
}

impl Drop for FreshBundleGuardChirho {
    fn drop(&mut self) {
        if !self.committed_chirho {
            let _ = std::fs::remove_dir_all(&self.path_chirho);
        }
    }
}

/// Author and self-verify one fresh signed roster bundle.
pub fn author_signed_roster_bundle_chirho(
    input_path_chirho: &Path,
    operator_sign_root_chirho: &Path,
    output_dir_chirho: &Path,
) -> Result<RosterAuthoringReportChirho> {
    let input_chirho = read_authoring_input_chirho(input_path_chirho)?;
    validate_authoring_input_chirho(&input_chirho)?;
    if output_dir_chirho.exists() {
        bail!("RosterAuthoringOutputAlreadyExistsChirho");
    }
    create_private_bundle_dir_chirho(output_dir_chirho)?;
    let mut bundle_guard_chirho = FreshBundleGuardChirho {
        path_chirho: output_dir_chirho.to_path_buf(),
        committed_chirho: false,
    };

    let operator_key_id_chirho = existing_keypair_pubkey_hex_chirho(operator_sign_root_chirho)
        .context("RosterAuthoringOperatorCustodyRefusedChirho")?;
    let mut lines_chirho = Vec::with_capacity(
        input_chirho.members_chirho.len() * 2 + input_chirho.preferred_leaders_chirho.len(),
    );
    for member_chirho in &input_chirho.members_chirho {
        let seq_chirho = lines_chirho.len() as u64;
        let mut membership_chirho = MembershipRosterRecordChirho {
            schema_chirho: MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            action_chirho: MembershipActionChirho::AddNodeChirho,
            node_pubkey_hex_chirho: member_chirho.node_pubkey_hex_chirho.clone(),
            region_label_chirho: member_chirho.region_label_chirho.clone(),
            at_ms_chirho: input_chirho.at_ms_chirho,
            operator_key_id_chirho: operator_key_id_chirho.clone(),
            sig_chirho: String::new(),
        };
        membership_chirho.sig_chirho = sign_exact_operator_message_chirho(
            operator_sign_root_chirho,
            &operator_key_id_chirho,
            &unsigned_membership_roster_message_chirho(&membership_chirho)?,
        )?;
        lines_chirho.push(serde_json::to_vec(&membership_chirho)?);

        let seq_chirho = lines_chirho.len() as u64;
        let mut network_chirho = NodeNetworkRecordChirho {
            schema_chirho: NODE_NETWORK_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            node_pubkey_hex_chirho: member_chirho.node_pubkey_hex_chirho.clone(),
            raft_id_chirho: member_chirho.raft_id_chirho,
            wg_pubkey_chirho: member_chirho.wg_pubkey_chirho.clone(),
            mesh_ip_chirho: member_chirho.mesh_ip_chirho.clone(),
            endpoint_chirho: member_chirho.endpoint_chirho.clone(),
            at_ms_chirho: input_chirho.at_ms_chirho,
            operator_key_id_chirho: operator_key_id_chirho.clone(),
            sig_chirho: String::new(),
        };
        network_chirho.sig_chirho = sign_exact_operator_message_chirho(
            operator_sign_root_chirho,
            &operator_key_id_chirho,
            &unsigned_node_network_record_message_chirho(&network_chirho)?,
        )?;
        lines_chirho.push(serde_json::to_vec(&network_chirho)?);
    }
    for preference_chirho in &input_chirho.preferred_leaders_chirho {
        let seq_chirho = lines_chirho.len() as u64;
        let mut preferred_chirho = PreferredLeaderRecordChirho {
            schema_chirho: PREFERRED_LEADER_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            group_id_chirho: preference_chirho.group_id_chirho.clone(),
            preferred_leader_raft_id_chirho: preference_chirho.preferred_leader_raft_id_chirho,
            at_ms_chirho: input_chirho.at_ms_chirho,
            operator_key_id_chirho: operator_key_id_chirho.clone(),
            sig_chirho: String::new(),
        };
        preferred_chirho.sig_chirho = sign_exact_operator_message_chirho(
            operator_sign_root_chirho,
            &operator_key_id_chirho,
            &unsigned_preferred_leader_record_message_chirho(&preferred_chirho)?,
        )?;
        lines_chirho.push(serde_json::to_vec(&preferred_chirho)?);
    }

    let mut head_chirho = MembershipRosterHeadChirho {
        schema_chirho: MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO.to_string(),
        roster_record_count_chirho: lines_chirho.len() as u64,
        roster_prefix_digest_chirho: roster_prefix_digest_chirho(&lines_chirho),
        at_ms_chirho: input_chirho.at_ms_chirho,
        operator_key_id_chirho: operator_key_id_chirho.clone(),
        sig_chirho: String::new(),
    };
    head_chirho.sig_chirho = sign_exact_operator_message_chirho(
        operator_sign_root_chirho,
        &operator_key_id_chirho,
        &unsigned_membership_roster_head_message_chirho(&head_chirho)?,
    )?;
    let head_bytes_chirho = serde_json::to_vec(&head_chirho)?;
    self_verify_bundle_chirho(
        &input_chirho,
        &operator_key_id_chirho,
        &lines_chirho,
        &head_bytes_chirho,
    )?;

    let mut roster_bytes_chirho = Vec::new();
    for line_chirho in &lines_chirho {
        roster_bytes_chirho.extend_from_slice(line_chirho);
        roster_bytes_chirho.push(b'\n');
    }
    let roster_file_chirho = output_dir_chirho.join(ROSTER_OUTPUT_FILE_CHIRHO);
    let roster_head_file_chirho = output_dir_chirho.join(ROSTER_HEAD_OUTPUT_FILE_CHIRHO);
    write_private_new_file_chirho(&roster_file_chirho, &roster_bytes_chirho)?;
    write_private_new_file_chirho(&roster_head_file_chirho, &head_bytes_chirho)?;
    File::open(output_dir_chirho)
        .context("RosterAuthoringOutputDirectoryOpenRefusedChirho")?
        .sync_all()
        .context("RosterAuthoringOutputDirectorySyncRefusedChirho")?;

    bundle_guard_chirho.committed_chirho = true;
    Ok(RosterAuthoringReportChirho {
        schema_chirho: ROSTER_AUTHORING_REPORT_SCHEMA_CHIRHO,
        operator_key_id_chirho,
        member_count_chirho: input_chirho.members_chirho.len(),
        preferred_leader_count_chirho: input_chirho.preferred_leaders_chirho.len(),
        roster_record_count_chirho: lines_chirho.len(),
        roster_blake3_chirho: blake3::hash(&roster_bytes_chirho).to_hex().to_string(),
        roster_head_blake3_chirho: blake3::hash(&head_bytes_chirho).to_hex().to_string(),
        roster_file_chirho,
        roster_head_file_chirho,
    })
}

fn read_authoring_input_chirho(path_chirho: &Path) -> Result<RosterAuthoringInputChirho> {
    let metadata_chirho = std::fs::symlink_metadata(path_chirho)
        .context("RosterAuthoringInputInspectRefusedChirho")?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_file() {
        bail!("RosterAuthoringInputTypeRefusedChirho");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata_chirho.permissions().mode() & 0o077 != 0 {
            bail!("RosterAuthoringInputModeRefusedChirho");
        }
    }
    if metadata_chirho.len() > MAX_AUTHORING_INPUT_BYTES_CHIRHO {
        bail!("RosterAuthoringInputSizeRefusedChirho");
    }
    let mut bytes_chirho = Vec::new();
    File::open(path_chirho)
        .context("RosterAuthoringInputOpenRefusedChirho")?
        .take(MAX_AUTHORING_INPUT_BYTES_CHIRHO + 1)
        .read_to_end(&mut bytes_chirho)
        .context("RosterAuthoringInputReadRefusedChirho")?;
    if bytes_chirho.len() as u64 > MAX_AUTHORING_INPUT_BYTES_CHIRHO {
        bail!("RosterAuthoringInputSizeRefusedChirho");
    }
    serde_json::from_slice(&bytes_chirho).context("RosterAuthoringInputParseRefusedChirho")
}

fn validate_authoring_input_chirho(input_chirho: &RosterAuthoringInputChirho) -> Result<()> {
    if input_chirho.schema_chirho != ROSTER_AUTHORING_INPUT_SCHEMA_CHIRHO {
        bail!("RosterAuthoringSchemaRefusedChirho");
    }
    if input_chirho.at_ms_chirho == 0 {
        bail!("RosterAuthoringTimestampRefusedChirho");
    }
    if input_chirho.members_chirho.is_empty()
        || input_chirho.members_chirho.len() > MAX_ROSTER_MEMBERS_CHIRHO
    {
        bail!("RosterAuthoringMemberPopulationRefusedChirho");
    }
    let mut node_ids_chirho = BTreeSet::new();
    let mut raft_ids_chirho = BTreeSet::new();
    let mut mesh_ips_chirho = BTreeSet::new();
    let mut wg_keys_chirho = BTreeSet::new();
    let mut endpoints_chirho = BTreeSet::new();
    for member_chirho in &input_chirho.members_chirho {
        validate_node_pubkey_chirho(&member_chirho.node_pubkey_hex_chirho)?;
        validate_label_chirho(
            &member_chirho.region_label_chirho,
            "RosterAuthoringRegionRefusedChirho",
        )?;
        if member_chirho.raft_id_chirho == 0 {
            bail!("RosterAuthoringRaftIdRefusedChirho");
        }
        let mesh_ip_chirho = member_chirho
            .mesh_ip_chirho
            .parse::<std::net::IpAddr>()
            .map_err(|_| anyhow::anyhow!("RosterAuthoringMeshIpRefusedChirho"))?;
        let private_chirho = match mesh_ip_chirho {
            std::net::IpAddr::V4(ip_chirho) => ip_chirho.is_private() || ip_chirho.is_loopback(),
            std::net::IpAddr::V6(ip_chirho) => {
                ip_chirho.is_loopback() || (ip_chirho.segments()[0] & 0xfe00) == 0xfc00
            }
        };
        if !private_chirho {
            bail!("RosterAuthoringMeshIpScopeRefusedChirho");
        }
        let wg_bytes_chirho = BASE64_CHIRHO
            .decode(member_chirho.wg_pubkey_chirho.as_bytes())
            .map_err(|_| anyhow::anyhow!("RosterAuthoringWireGuardKeyRefusedChirho"))?;
        if wg_bytes_chirho.len() != WIREGUARD_PUBLIC_KEY_BYTES_CHIRHO {
            bail!("RosterAuthoringWireGuardKeyRefusedChirho");
        }
        validate_endpoint_chirho(&member_chirho.endpoint_chirho)?;
        if !node_ids_chirho.insert(&member_chirho.node_pubkey_hex_chirho)
            || !raft_ids_chirho.insert(member_chirho.raft_id_chirho)
            || !mesh_ips_chirho.insert(&member_chirho.mesh_ip_chirho)
            || !wg_keys_chirho.insert(&member_chirho.wg_pubkey_chirho)
            || !endpoints_chirho.insert(&member_chirho.endpoint_chirho)
        {
            bail!("RosterAuthoringCoordinateCollisionRefusedChirho");
        }
    }
    let mut preferred_groups_chirho = BTreeSet::new();
    for preferred_chirho in &input_chirho.preferred_leaders_chirho {
        validate_label_chirho(
            &preferred_chirho.group_id_chirho,
            "RosterAuthoringPreferredGroupRefusedChirho",
        )?;
        if !preferred_groups_chirho.insert(&preferred_chirho.group_id_chirho) {
            bail!("RosterAuthoringPreferredGroupDuplicateRefusedChirho");
        }
        if !raft_ids_chirho.contains(&preferred_chirho.preferred_leader_raft_id_chirho) {
            bail!("RosterAuthoringPreferredLeaderNonmemberRefusedChirho");
        }
    }
    Ok(())
}

fn validate_node_pubkey_chirho(value_chirho: &str) -> Result<()> {
    if value_chirho.len() != ED25519_PUBLIC_KEY_HEX_BYTES_CHIRHO
        || !value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
    {
        bail!("RosterAuthoringNodeKeyRefusedChirho");
    }
    let dummy_signature_chirho = "00".repeat(ED25519_SIGNATURE_HEX_BYTES_CHIRHO / 2);
    let _ = verify_with_pubkey_chirho(
        value_chirho,
        b"roster-authoring-node-key-validation-chirho",
        &dummy_signature_chirho,
    )
    .context("RosterAuthoringNodeKeyRefusedChirho")?;
    Ok(())
}

fn validate_label_chirho(value_chirho: &str, refusal_chirho: &str) -> Result<()> {
    if value_chirho.is_empty()
        || value_chirho.len() > MAX_LABEL_BYTES_CHIRHO
        || !value_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_alphanumeric() || matches!(byte_chirho, b'-' | b'_' | b':' | b'.')
        })
    {
        bail!("{refusal_chirho}");
    }
    Ok(())
}

fn validate_endpoint_chirho(value_chirho: &str) -> Result<()> {
    if value_chirho.is_empty()
        || value_chirho.len() > MAX_LABEL_BYTES_CHIRHO
        || value_chirho.bytes().any(|byte_chirho| {
            byte_chirho.is_ascii_whitespace()
                || byte_chirho.is_ascii_control()
                || matches!(byte_chirho, b'/' | b'@')
        })
    {
        bail!("RosterAuthoringEndpointRefusedChirho");
    }
    let Some((host_chirho, port_chirho)) = value_chirho.rsplit_once(':') else {
        bail!("RosterAuthoringEndpointRefusedChirho");
    };
    if host_chirho.is_empty()
        || port_chirho
            .parse::<u16>()
            .ok()
            .filter(|port_chirho| *port_chirho != 0)
            .is_none()
    {
        bail!("RosterAuthoringEndpointRefusedChirho");
    }
    Ok(())
}

fn sign_exact_operator_message_chirho(
    operator_root_chirho: &Path,
    expected_key_id_chirho: &str,
    message_chirho: &[u8],
) -> Result<String> {
    let possession_chirho =
        sign_with_existing_key_possession_chirho(operator_root_chirho, message_chirho)
            .context("RosterAuthoringOperatorSigningRefusedChirho")?;
    if possession_chirho.key_id_chirho() != expected_key_id_chirho {
        bail!("RosterAuthoringOperatorKeyChangedRefusedChirho");
    }
    Ok(possession_chirho.into_signature_hex_chirho())
}

fn self_verify_bundle_chirho(
    input_chirho: &RosterAuthoringInputChirho,
    operator_key_id_chirho: &str,
    lines_chirho: &[Vec<u8>],
    head_bytes_chirho: &[u8],
) -> Result<()> {
    let membership_chirho = verify_membership_roster_with_head_chirho(
        lines_chirho,
        head_bytes_chirho,
        operator_key_id_chirho,
    )
    .context("RosterAuthoringMembershipSelfVerificationRefusedChirho")?;
    if membership_chirho.active_count_chirho() != input_chirho.members_chirho.len() {
        bail!("RosterAuthoringMembershipPopulationRefusedChirho");
    }
    let network_chirho = verify_node_network_records_chirho(lines_chirho, operator_key_id_chirho)
        .context("RosterAuthoringNetworkSelfVerificationRefusedChirho")?;
    if network_chirho.len() != input_chirho.members_chirho.len() {
        bail!("RosterAuthoringNetworkPopulationRefusedChirho");
    }
    let preferred_chirho =
        verify_preferred_leader_records_chirho(lines_chirho, operator_key_id_chirho)
            .context("RosterAuthoringPreferenceSelfVerificationRefusedChirho")?;
    if preferred_chirho.len() != input_chirho.preferred_leaders_chirho.len() {
        bail!("RosterAuthoringPreferencePopulationRefusedChirho");
    }
    for member_chirho in &input_chirho.members_chirho {
        let (derived_chirho, evidence_chirho) = derive_elector_config_chirho(
            lines_chirho,
            head_bytes_chirho,
            operator_key_id_chirho,
            &member_chirho.node_pubkey_hex_chirho,
        )
        .context("RosterAuthoringElectorSelfVerificationRefusedChirho")?;
        if derived_chirho.local_raft_id_chirho != member_chirho.raft_id_chirho
            || evidence_chirho.member_count_chirho != input_chirho.members_chirho.len()
        {
            bail!("RosterAuthoringElectorCoordinateRefusedChirho");
        }
    }
    let local_node_chirho = &input_chirho.members_chirho[0].node_pubkey_hex_chirho;
    for preference_chirho in &input_chirho.preferred_leaders_chirho {
        let derived_chirho = derive_preferred_leader_chirho(
            lines_chirho,
            head_bytes_chirho,
            operator_key_id_chirho,
            local_node_chirho,
            &preference_chirho.group_id_chirho,
        )
        .context("RosterAuthoringPreferenceDerivationRefusedChirho")?;
        if derived_chirho != Some(preference_chirho.preferred_leader_raft_id_chirho) {
            bail!("RosterAuthoringPreferenceDerivationRefusedChirho");
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_bundle_dir_chirho(path_chirho: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let mut builder_chirho = std::fs::DirBuilder::new();
    builder_chirho.mode(0o700);
    builder_chirho
        .create(path_chirho)
        .context("RosterAuthoringOutputDirectoryCreateRefusedChirho")?;
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o700))
        .context("RosterAuthoringOutputDirectoryModeRefusedChirho")
}

#[cfg(not(unix))]
fn create_private_bundle_dir_chirho(path_chirho: &Path) -> Result<()> {
    std::fs::create_dir(path_chirho).context("RosterAuthoringOutputDirectoryCreateRefusedChirho")
}

#[cfg(unix)]
fn write_private_new_file_chirho(path_chirho: &Path, bytes_chirho: &[u8]) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file_chirho = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path_chirho)
        .context("RosterAuthoringOutputCreateRefusedChirho")?;
    file_chirho
        .write_all(bytes_chirho)
        .context("RosterAuthoringOutputWriteRefusedChirho")?;
    file_chirho
        .sync_all()
        .context("RosterAuthoringOutputSyncRefusedChirho")?;
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o600))
        .context("RosterAuthoringOutputModeRefusedChirho")
}

#[cfg(not(unix))]
fn write_private_new_file_chirho(path_chirho: &Path, bytes_chirho: &[u8]) -> Result<()> {
    let mut file_chirho = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path_chirho)
        .context("RosterAuthoringOutputCreateRefusedChirho")?;
    file_chirho
        .write_all(bytes_chirho)
        .context("RosterAuthoringOutputWriteRefusedChirho")?;
    file_chirho
        .sync_all()
        .context("RosterAuthoringOutputSyncRefusedChirho")
}
