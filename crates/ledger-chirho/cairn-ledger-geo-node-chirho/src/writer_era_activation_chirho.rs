// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! One-time operator-authorized transition from legacy-local to elected writer authority.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/serve-write-forwarding-design-chirho.md`.

use anyhow::{bail, Context, Result};
use cairn_signer_chirho::signer_chirho::{
    sign_with_existing_key_possession_chirho, verify_with_pubkey_chirho,
};
use cairn_writer_elector_http_chirho::cluster_file_config_chirho::{
    load_cluster_node_file_config_chirho, verify_cluster_node_file_config_custody_chirho,
};
use cairn_writer_head_chirho::head_transition_authority_chirho::{
    HeadTransitionAuthorityPortChirho, HeadTransitionCommitActionChirho,
    HeadTransitionCommitScopeChirho,
};
use cairn_writer_head_chirho::resident_writer_chirho::canonical_filesystem_path_digest_chirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_for_root_chirho, writer_authority_era_chirho, ConsistencyGroupIdChirho,
    WriterAuthorityEraChirho,
};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const WRITER_ERA_ACTIVATION_CANDIDATE_SCHEMA_V1_CHIRHO: &str =
    "writer-era-activation-candidate-v1-chirho";
pub const WRITER_ERA_ACTIVATION_AUTHORIZATION_SCHEMA_V1_CHIRHO: &str =
    "writer-era-activation-authorization-v1-chirho";
pub const MAX_WRITER_ERA_ACTIVATION_DOCUMENT_BYTES_CHIRHO: u64 = 16 * 1024;
pub const MAX_WRITER_ERA_ACTIVATION_WINDOW_MS_CHIRHO: u64 = 24 * 60 * 60 * 1_000;
const DEFAULT_WRITER_ERA_ACTIVATION_WINDOW_MS_CHIRHO: u64 = 15 * 60 * 1_000;
const WRITER_ERA_ACTIVATION_CLOCK_SKEW_MS_CHIRHO: u64 = 60 * 1_000;

/// Host-measured, non-authoritative activation coordinates returned for offline signing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterEraActivationCandidateChirho {
    pub schema_chirho: String,
    pub canonical_root_digest_chirho: String,
    pub root_device_chirho: u64,
    pub root_inode_chirho: u64,
    pub consistency_group_id_chirho: String,
    pub owner_node_id_chirho: String,
    pub roster_head_blake3_chirho: String,
    pub cluster_config_blake3_chirho: String,
    pub operator_key_id_chirho: String,
}

/// Offline operator authorization for exactly one fresh-root elected-mode cutover.
///
/// The filesystem identity prevents reuse after whole-root replacement. The exact parsed cluster
/// bytes and roster-head digest prevent carrying an approval across election or mesh changes. The
/// live elected authority remains the only component that can consume this record and issue the
/// composite fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterEraActivationAuthorizationChirho {
    pub schema_chirho: String,
    pub canonical_root_digest_chirho: String,
    pub root_device_chirho: u64,
    pub root_inode_chirho: u64,
    pub consistency_group_id_chirho: String,
    pub owner_node_id_chirho: String,
    pub roster_head_blake3_chirho: String,
    pub cluster_config_blake3_chirho: String,
    pub not_before_ms_chirho: u64,
    pub not_after_ms_chirho: u64,
    pub operator_key_id_chirho: String,
    pub sig_chirho: String,
}

/// Measure one fresh root and the exact private cluster configuration that will serve it.
///
/// This creates no authority and signs nothing. The output is safe to move to the offline
/// operator-signing machine; the operator private key never reaches the host.
pub fn inspect_writer_era_activation_candidate_chirho(
    root_chirho: &Path,
    cluster_config_path_chirho: &Path,
) -> Result<WriterEraActivationCandidateChirho> {
    if writer_authority_era_chirho(root_chirho)? != WriterAuthorityEraChirho::LocalChirho {
        bail!("GeoWriterEraActivationCandidateNotFreshChirho");
    }
    verify_cluster_node_file_config_custody_chirho(root_chirho, cluster_config_path_chirho)
        .context("GeoWriterEraActivationClusterConfigCustodyRefusedChirho")?;
    let loaded_chirho = load_cluster_node_file_config_chirho(cluster_config_path_chirho)
        .context("GeoWriterEraActivationClusterConfigRefusedChirho")?;
    let actual_group_chirho = consistency_group_for_root_chirho(root_chirho)?;
    if loaded_chirho.cluster_chirho.group_chirho != actual_group_chirho {
        bail!("GeoWriterEraActivationGroupRefusedChirho");
    }
    let local_nodes_chirho = loaded_chirho
        .cluster_chirho
        .voters_chirho
        .iter()
        .filter(|(raft_id_chirho, _node_chirho)| {
            *raft_id_chirho == loaded_chirho.cluster_chirho.local_raft_id_chirho
        })
        .map(|(_raft_id_chirho, node_chirho)| node_chirho.0.clone())
        .collect::<Vec<_>>();
    let [owner_node_id_chirho] = local_nodes_chirho.as_slice() else {
        bail!("GeoWriterEraActivationOwnerRefusedChirho");
    };
    if loaded_chirho
        .cluster_chirho
        .learners_chirho
        .iter()
        .any(|(raft_id_chirho, _node_chirho)| {
            *raft_id_chirho == loaded_chirho.cluster_chirho.local_raft_id_chirho
        })
    {
        bail!("GeoWriterEraActivationOwnerRefusedChirho");
    }
    let membership_chirho = loaded_chirho
        .cluster_chirho
        .membership_control_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("GeoWriterEraActivationRosterUnavailableChirho"))?;
    if loaded_chirho
        .writer_era_activation_authorization_chirho
        .is_none()
    {
        bail!("GeoWriterEraActivationAuthorizationPathMissingChirho");
    }
    let canonical_root_chirho = root_chirho
        .canonicalize()
        .context("GeoWriterEraActivationRootRefusedChirho")?;
    let metadata_chirho = std::fs::metadata(&canonical_root_chirho)
        .context("GeoWriterEraActivationRootRefusedChirho")?;
    let roster_head_chirho = read_bounded_regular_file_chirho(
        &membership_chirho
            .roster_authority_chirho
            .roster_head_path_chirho,
    )
    .context("GeoWriterEraActivationRosterHeadUnavailableChirho")?;
    Ok(WriterEraActivationCandidateChirho {
        schema_chirho: WRITER_ERA_ACTIVATION_CANDIDATE_SCHEMA_V1_CHIRHO.to_owned(),
        canonical_root_digest_chirho: canonical_filesystem_path_digest_chirho(
            &canonical_root_chirho,
        )?,
        root_device_chirho: root_device_chirho(&metadata_chirho),
        root_inode_chirho: root_inode_chirho(&metadata_chirho),
        consistency_group_id_chirho: actual_group_chirho.canonical_id_chirho(),
        owner_node_id_chirho: owner_node_id_chirho.clone(),
        roster_head_blake3_chirho: blake3::hash(&roster_head_chirho).to_hex().to_string(),
        cluster_config_blake3_chirho: loaded_chirho.config_blake3_chirho,
        operator_key_id_chirho: membership_chirho
            .roster_authority_chirho
            .operator_pubkey_hex_chirho
            .clone(),
    })
}

/// Sign one host-measured candidate with an already-provisioned offline operator key.
pub fn sign_writer_era_activation_candidate_chirho(
    candidate_chirho: &WriterEraActivationCandidateChirho,
    operator_sign_root_chirho: &Path,
) -> Result<WriterEraActivationAuthorizationChirho> {
    sign_writer_era_activation_candidate_at_chirho(
        candidate_chirho,
        operator_sign_root_chirho,
        now_ms_chirho()?,
    )
}

fn sign_writer_era_activation_candidate_at_chirho(
    candidate_chirho: &WriterEraActivationCandidateChirho,
    operator_sign_root_chirho: &Path,
    now_ms_chirho: u64,
) -> Result<WriterEraActivationAuthorizationChirho> {
    if candidate_chirho.schema_chirho != WRITER_ERA_ACTIVATION_CANDIDATE_SCHEMA_V1_CHIRHO {
        bail!("GeoWriterEraActivationCandidateSchemaRefusedChirho");
    }
    let mut authorization_chirho = WriterEraActivationAuthorizationChirho {
        schema_chirho: WRITER_ERA_ACTIVATION_AUTHORIZATION_SCHEMA_V1_CHIRHO.to_owned(),
        canonical_root_digest_chirho: candidate_chirho.canonical_root_digest_chirho.clone(),
        root_device_chirho: candidate_chirho.root_device_chirho,
        root_inode_chirho: candidate_chirho.root_inode_chirho,
        consistency_group_id_chirho: candidate_chirho.consistency_group_id_chirho.clone(),
        owner_node_id_chirho: candidate_chirho.owner_node_id_chirho.clone(),
        roster_head_blake3_chirho: candidate_chirho.roster_head_blake3_chirho.clone(),
        cluster_config_blake3_chirho: candidate_chirho.cluster_config_blake3_chirho.clone(),
        not_before_ms_chirho: now_ms_chirho
            .saturating_sub(WRITER_ERA_ACTIVATION_CLOCK_SKEW_MS_CHIRHO),
        not_after_ms_chirho: now_ms_chirho
            .checked_add(DEFAULT_WRITER_ERA_ACTIVATION_WINDOW_MS_CHIRHO)
            .ok_or_else(|| anyhow::anyhow!("GeoWriterEraActivationWindowRefusedChirho"))?,
        operator_key_id_chirho: candidate_chirho.operator_key_id_chirho.clone(),
        sig_chirho: String::new(),
    };
    let message_chirho =
        unsigned_writer_era_activation_authorization_message_chirho(&authorization_chirho)?;
    let possession_chirho =
        sign_with_existing_key_possession_chirho(operator_sign_root_chirho, &message_chirho)
            .context("GeoWriterEraActivationOperatorCustodyRefusedChirho")?;
    if possession_chirho.key_id_chirho() != authorization_chirho.operator_key_id_chirho {
        bail!("GeoWriterEraActivationOperatorRefusedChirho");
    }
    authorization_chirho.sig_chirho = possession_chirho.into_signature_hex_chirho();
    Ok(authorization_chirho)
}

/// Canonical message signed by the offline operator.
pub fn unsigned_writer_era_activation_authorization_message_chirho(
    authorization_chirho: &WriterEraActivationAuthorizationChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = authorization_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

/// Require the durable one-way latch before any remote-owner process serves the root.
pub(crate) fn require_elected_writer_era_chirho(root_chirho: &Path) -> Result<()> {
    if writer_authority_era_chirho(root_chirho)? != WriterAuthorityEraChirho::ElectedChirho {
        bail!("GeoWriterEraNotActivatedChirho");
    }
    Ok(())
}

/// Consume one exact authorization through the live shared-elector head-transition port.
#[allow(clippy::too_many_arguments)]
pub(crate) fn activate_fresh_writer_era_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    local_node_id_chirho: &str,
    roster_head_path_chirho: &Path,
    operator_pubkey_hex_chirho: &str,
    parsed_cluster_config_blake3_chirho: &str,
    authorization_path_chirho: &Path,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<u64> {
    if writer_authority_era_chirho(root_chirho)? == WriterAuthorityEraChirho::ElectedChirho {
        bail!("GeoWriterEraAlreadyActivatedChirho");
    }
    let authorization_chirho =
        load_activation_authorization_chirho(root_chirho, authorization_path_chirho)?;
    verify_activation_authorization_chirho(
        root_chirho,
        group_chirho,
        local_node_id_chirho,
        roster_head_path_chirho,
        operator_pubkey_hex_chirho,
        parsed_cluster_config_blake3_chirho,
        &authorization_chirho,
        now_ms_chirho()?,
    )?;

    struct ActivationActionChirho {
        observed_epoch_chirho: Option<u64>,
    }

    impl HeadTransitionCommitActionChirho for ActivationActionChirho {
        fn call_chirho(&mut self, scope_chirho: HeadTransitionCommitScopeChirho<'_>) -> Result<()> {
            self.observed_epoch_chirho = Some(scope_chirho.writer_fence_epoch_chirho());
            Ok(())
        }
    }

    let mut action_chirho = ActivationActionChirho {
        observed_epoch_chirho: None,
    };
    authority_chirho
        .with_elected_head_transition_scope_chirho(root_chirho, &mut action_chirho)
        .context("GeoWriterEraActivationAuthorityRefusedChirho")?;
    let epoch_chirho = action_chirho
        .observed_epoch_chirho
        .ok_or_else(|| anyhow::anyhow!("GeoWriterEraActivationScopeMissingChirho"))?;
    require_elected_writer_era_chirho(root_chirho)?;
    Ok(epoch_chirho)
}

fn load_activation_authorization_chirho(
    root_chirho: &Path,
    path_chirho: &Path,
) -> Result<WriterEraActivationAuthorizationChirho> {
    if !path_chirho.is_absolute() {
        bail!("GeoWriterEraActivationPathNotAbsoluteChirho");
    }
    let root_metadata_chirho = std::fs::symlink_metadata(root_chirho)
        .context("GeoWriterEraActivationRootRefusedChirho")?;
    let metadata_chirho = std::fs::symlink_metadata(path_chirho)
        .context("GeoWriterEraActivationAuthorizationUnavailableChirho")?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_file() {
        bail!("GeoWriterEraActivationFileTypeRefusedChirho");
    }
    if !private_file_mode_chirho(&metadata_chirho)
        || !same_owner_chirho(&root_metadata_chirho, &metadata_chirho)
    {
        bail!("GeoWriterEraActivationFileCustodyRefusedChirho");
    }
    let bytes_chirho = read_bounded_regular_file_chirho(path_chirho)
        .context("GeoWriterEraActivationFileRefusedChirho")?;
    serde_json::from_slice(&bytes_chirho).context("GeoWriterEraActivationEncodingRefusedChirho")
}

#[allow(clippy::too_many_arguments)]
fn verify_activation_authorization_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    local_node_id_chirho: &str,
    roster_head_path_chirho: &Path,
    operator_pubkey_hex_chirho: &str,
    parsed_cluster_config_blake3_chirho: &str,
    authorization_chirho: &WriterEraActivationAuthorizationChirho,
    now_ms_chirho: u64,
) -> Result<()> {
    if authorization_chirho.schema_chirho != WRITER_ERA_ACTIVATION_AUTHORIZATION_SCHEMA_V1_CHIRHO {
        bail!("GeoWriterEraActivationSchemaRefusedChirho");
    }
    if authorization_chirho.operator_key_id_chirho != operator_pubkey_hex_chirho {
        bail!("GeoWriterEraActivationOperatorRefusedChirho");
    }
    let message_chirho =
        unsigned_writer_era_activation_authorization_message_chirho(authorization_chirho)?;
    if !verify_with_pubkey_chirho(
        operator_pubkey_hex_chirho,
        &message_chirho,
        &authorization_chirho.sig_chirho,
    )
    .context("GeoWriterEraActivationSignatureRefusedChirho")?
    {
        bail!("GeoWriterEraActivationSignatureRefusedChirho");
    }
    if authorization_chirho.consistency_group_id_chirho != group_chirho.canonical_id_chirho() {
        bail!("GeoWriterEraActivationGroupRefusedChirho");
    }
    if authorization_chirho.owner_node_id_chirho != local_node_id_chirho {
        bail!("GeoWriterEraActivationOwnerRefusedChirho");
    }
    if authorization_chirho.cluster_config_blake3_chirho != parsed_cluster_config_blake3_chirho {
        bail!("GeoWriterEraActivationClusterConfigRefusedChirho");
    }
    let canonical_root_chirho = root_chirho
        .canonicalize()
        .context("GeoWriterEraActivationRootRefusedChirho")?;
    let metadata_chirho = std::fs::metadata(&canonical_root_chirho)
        .context("GeoWriterEraActivationRootRefusedChirho")?;
    if authorization_chirho.canonical_root_digest_chirho
        != canonical_filesystem_path_digest_chirho(&canonical_root_chirho)?
        || authorization_chirho.root_device_chirho != root_device_chirho(&metadata_chirho)
        || authorization_chirho.root_inode_chirho != root_inode_chirho(&metadata_chirho)
    {
        bail!("GeoWriterEraActivationRootRefusedChirho");
    }
    let roster_head_chirho = read_bounded_regular_file_chirho(roster_head_path_chirho)
        .context("GeoWriterEraActivationRosterHeadUnavailableChirho")?;
    if authorization_chirho.roster_head_blake3_chirho
        != blake3::hash(&roster_head_chirho).to_hex().to_string()
    {
        bail!("GeoWriterEraActivationRosterRefusedChirho");
    }
    if authorization_chirho.not_before_ms_chirho == 0
        || authorization_chirho.not_after_ms_chirho <= authorization_chirho.not_before_ms_chirho
        || authorization_chirho
            .not_after_ms_chirho
            .saturating_sub(authorization_chirho.not_before_ms_chirho)
            > MAX_WRITER_ERA_ACTIVATION_WINDOW_MS_CHIRHO
        || now_ms_chirho < authorization_chirho.not_before_ms_chirho
        || now_ms_chirho > authorization_chirho.not_after_ms_chirho
    {
        bail!("GeoWriterEraActivationWindowRefusedChirho");
    }
    Ok(())
}

fn read_bounded_regular_file_chirho(path_chirho: &Path) -> Result<Vec<u8>> {
    let metadata_chirho = std::fs::symlink_metadata(path_chirho)?;
    if metadata_chirho.file_type().is_symlink()
        || !metadata_chirho.is_file()
        || metadata_chirho.len() > MAX_WRITER_ERA_ACTIVATION_DOCUMENT_BYTES_CHIRHO
    {
        bail!("bounded activation input must be one regular file");
    }
    let mut bytes_chirho = Vec::new();
    std::fs::File::open(path_chirho)?
        .take(MAX_WRITER_ERA_ACTIVATION_DOCUMENT_BYTES_CHIRHO + 1)
        .read_to_end(&mut bytes_chirho)?;
    if bytes_chirho.len() as u64 > MAX_WRITER_ERA_ACTIVATION_DOCUMENT_BYTES_CHIRHO {
        bail!("bounded activation input exceeds its read limit");
    }
    Ok(bytes_chirho)
}

fn now_ms_chirho() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before Unix epoch")?
        .as_millis()
        .try_into()
        .context("system clock does not fit u64 milliseconds")
}

#[cfg(unix)]
fn private_file_mode_chirho(metadata_chirho: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata_chirho.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_file_mode_chirho(_metadata_chirho: &std::fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn same_owner_chirho(left_chirho: &std::fs::Metadata, right_chirho: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left_chirho.uid() == right_chirho.uid()
}

#[cfg(not(unix))]
fn same_owner_chirho(_left_chirho: &std::fs::Metadata, _right_chirho: &std::fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn root_device_chirho(metadata_chirho: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata_chirho.dev()
}

#[cfg(not(unix))]
fn root_device_chirho(_metadata_chirho: &std::fs::Metadata) -> u64 {
    0
}

#[cfg(unix)]
fn root_inode_chirho(metadata_chirho: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata_chirho.ino()
}

#[cfg(not(unix))]
fn root_inode_chirho(_metadata_chirho: &std::fs::Metadata) -> u64 {
    0
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_signer_chirho::signer_chirho;
    use cairn_writer_head_chirho::head_transition_authority_chirho::{
        with_elected_head_transition_scope_chirho, ElectedHeadTransitionScopeOutcomeChirho,
    };
    use std::cell::Cell;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct ProductionFencePortChirho {
        group_chirho: ConsistencyGroupIdChirho,
        geo_term_chirho: u64,
        calls_chirho: Cell<u64>,
    }

    impl HeadTransitionAuthorityPortChirho for ProductionFencePortChirho {
        fn with_elected_head_transition_scope_chirho(
            &self,
            root_chirho: &Path,
            action_chirho: &mut dyn HeadTransitionCommitActionChirho,
        ) -> Result<()> {
            self.calls_chirho
                .set(self.calls_chirho.get().saturating_add(1));
            let outcome_chirho: ElectedHeadTransitionScopeOutcomeChirho<()> =
                with_elected_head_transition_scope_chirho(
                    root_chirho,
                    &self.group_chirho,
                    self.geo_term_chirho,
                    None,
                    |scope_chirho| action_chirho.call_chirho(scope_chirho),
                );
            outcome_chirho.into_result_chirho()
        }
    }

    struct ActivationFixtureChirho {
        base_chirho: PathBuf,
        root_chirho: PathBuf,
        operator_root_chirho: PathBuf,
        roster_head_chirho: PathBuf,
        authorization_chirho: PathBuf,
        group_chirho: ConsistencyGroupIdChirho,
        node_id_chirho: String,
        operator_pubkey_chirho: String,
        config_blake3_chirho: String,
        candidate_chirho: WriterEraActivationCandidateChirho,
    }

    impl Drop for ActivationFixtureChirho {
        fn drop(&mut self) {
            let _ignored_chirho = std::fs::remove_dir_all(&self.base_chirho);
        }
    }

    fn temp_path_chirho(label_chirho: &str) -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "cairn-writer-era-activation-{label_chirho}-{}-{counter_chirho}-chirho",
            std::process::id()
        ))
    }

    fn write_private_chirho(path_chirho: &Path, bytes_chirho: &[u8]) {
        if let Some(parent_chirho) = path_chirho.parent() {
            std::fs::create_dir_all(parent_chirho).expect("create fixture parent");
        }
        std::fs::write(path_chirho, bytes_chirho).expect("write private fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o600))
                .expect("set private fixture mode");
        }
    }

    fn activation_fixture_chirho(label_chirho: &str) -> ActivationFixtureChirho {
        let base_chirho = temp_path_chirho(label_chirho);
        let root_chirho = base_chirho.join("root-chirho");
        let node_sign_root_chirho = base_chirho.join("node-sign-chirho");
        let operator_root_chirho = base_chirho.join("operator-sign-chirho");
        let roster_chirho = base_chirho.join("roster-chirho.jsonl");
        let roster_head_chirho = base_chirho.join("roster-head-chirho.json");
        let authorization_chirho = base_chirho.join("activation-chirho.json");
        let cluster_config_chirho = base_chirho.join("cluster-chirho.json");
        std::fs::create_dir_all(&root_chirho).expect("create activation root");
        let canonical_root_chirho = root_chirho.canonicalize().expect("canonical root");
        let node_id_chirho =
            signer_chirho::pubkey_hex_chirho(&node_sign_root_chirho).expect("node key");
        let operator_pubkey_chirho =
            signer_chirho::pubkey_hex_chirho(&operator_root_chirho).expect("operator key");
        write_private_chirho(&roster_chirho, b"{\"test_chirho\":\"roster\"}\n");
        write_private_chirho(&roster_head_chirho, b"{\"test_chirho\":\"head\"}\n");
        let cluster_bytes_chirho = format!(
            r#"{{
                "group_chirho": {{
                    "kind_chirho": "root",
                    "root_path_chirho": "{}"
                }},
                "local_raft_id_chirho": 1,
                "members_chirho": [
                    {{
                        "raft_id_chirho": 1,
                        "pubkey_chirho": "{node_id_chirho}",
                        "url_chirho": "http://127.0.0.1:8300",
                        "learner_chirho": false
                    }},
                    {{
                        "raft_id_chirho": 2,
                        "pubkey_chirho": "{}",
                        "url_chirho": "http://127.0.0.1:8301",
                        "learner_chirho": true
                    }}
                ],
                "durable_dir_chirho": "{}",
                "sign_root_chirho": "{}",
                "listen_addr_chirho": "127.0.0.1:8300",
                "tick_ms_chirho": 50,
                "writer_era_activation_authorization_chirho": "{}",
                "roster_authority_chirho": {{
                    "roster_path_chirho": "{}",
                    "roster_head_path_chirho": "{}",
                    "operator_pubkey_hex_chirho": "{operator_pubkey_chirho}"
                }},
                "membership_control_chirho": {{
                    "target_authority_chirho": {{"kind_chirho": "roster_wide"}},
                    "operator_token_env_chirho": "MISSING_TEST_TOKEN_CHIRHO"
                }}
            }}"#,
            canonical_root_chirho.display(),
            "b".repeat(64),
            base_chirho.join("raft-chirho").display(),
            node_sign_root_chirho.display(),
            authorization_chirho.display(),
            roster_chirho.display(),
            roster_head_chirho.display(),
        )
        .into_bytes();
        write_private_chirho(&cluster_config_chirho, &cluster_bytes_chirho);
        let candidate_chirho =
            inspect_writer_era_activation_candidate_chirho(&root_chirho, &cluster_config_chirho)
                .expect("inspect activation candidate");
        let group_chirho =
            consistency_group_for_root_chirho(&root_chirho).expect("derive root group");
        ActivationFixtureChirho {
            base_chirho,
            root_chirho,
            operator_root_chirho,
            roster_head_chirho,
            authorization_chirho,
            group_chirho,
            node_id_chirho,
            operator_pubkey_chirho,
            config_blake3_chirho: blake3::hash(&cluster_bytes_chirho).to_hex().to_string(),
            candidate_chirho,
        }
    }

    fn write_authorization_chirho(
        fixture_chirho: &ActivationFixtureChirho,
        authorization_chirho: &WriterEraActivationAuthorizationChirho,
    ) {
        write_private_chirho(
            &fixture_chirho.authorization_chirho,
            &serde_json::to_vec(authorization_chirho).expect("encode authorization"),
        );
    }

    fn sign_candidate_chirho(
        fixture_chirho: &ActivationFixtureChirho,
        candidate_chirho: &WriterEraActivationCandidateChirho,
    ) -> WriterEraActivationAuthorizationChirho {
        sign_writer_era_activation_candidate_chirho(
            candidate_chirho,
            &fixture_chirho.operator_root_chirho,
        )
        .expect("sign activation candidate")
    }

    fn activation_port_chirho(
        fixture_chirho: &ActivationFixtureChirho,
    ) -> ProductionFencePortChirho {
        ProductionFencePortChirho {
            group_chirho: fixture_chirho.group_chirho.clone(),
            geo_term_chirho: 7,
            calls_chirho: Cell::new(0),
        }
    }

    fn activate_chirho(
        fixture_chirho: &ActivationFixtureChirho,
        port_chirho: &ProductionFencePortChirho,
    ) -> Result<u64> {
        activate_fresh_writer_era_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.group_chirho,
            &fixture_chirho.node_id_chirho,
            &fixture_chirho.roster_head_chirho,
            &fixture_chirho.operator_pubkey_chirho,
            &fixture_chirho.config_blake3_chirho,
            &fixture_chirho.authorization_chirho,
            port_chirho,
        )
    }

    fn assert_refuses_before_fence_chirho(
        fixture_chirho: &ActivationFixtureChirho,
        authorization_chirho: &WriterEraActivationAuthorizationChirho,
        expected_chirho: &str,
    ) {
        write_authorization_chirho(fixture_chirho, authorization_chirho);
        let port_chirho = activation_port_chirho(fixture_chirho);
        let error_chirho = activate_chirho(fixture_chirho, &port_chirho)
            .expect_err("invalid authorization must refuse");
        assert_eq!(error_chirho.to_string(), expected_chirho);
        assert_eq!(port_chirho.calls_chirho.get(), 0);
        assert_eq!(
            writer_authority_era_chirho(&fixture_chirho.root_chirho).unwrap(),
            WriterAuthorityEraChirho::LocalChirho
        );
    }

    #[test]
    fn signed_exact_candidate_activates_one_durable_elected_fence_chirho() {
        let fixture_chirho = activation_fixture_chirho("success");
        let authorization_chirho =
            sign_candidate_chirho(&fixture_chirho, &fixture_chirho.candidate_chirho);
        write_authorization_chirho(&fixture_chirho, &authorization_chirho);
        let port_chirho = activation_port_chirho(&fixture_chirho);

        let epoch_chirho =
            activate_chirho(&fixture_chirho, &port_chirho).expect("exact authorization activates");

        assert!(epoch_chirho > 0);
        assert_eq!(port_chirho.calls_chirho.get(), 1);
        require_elected_writer_era_chirho(&fixture_chirho.root_chirho)
            .expect("durable elected latch is visible after activation");
        assert!(inspect_writer_era_activation_candidate_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.base_chirho.join("cluster-chirho.json")
        )
        .unwrap_err()
        .to_string()
        .contains("GeoWriterEraActivationCandidateNotFreshChirho"));
    }

    #[test]
    fn fresh_follower_root_named_refuses_without_calling_any_authority_chirho() {
        let fixture_chirho = activation_fixture_chirho("follower");

        let error_chirho = require_elected_writer_era_chirho(&fixture_chirho.root_chirho)
            .expect_err("fresh follower root must not serve");

        assert_eq!(error_chirho.to_string(), "GeoWriterEraNotActivatedChirho");
    }

    #[test]
    fn every_signed_binding_mismatch_refuses_before_authority_or_fence_chirho() {
        let root_fixture_chirho = activation_fixture_chirho("wrong-root");
        let mut wrong_root_chirho = root_fixture_chirho.candidate_chirho.clone();
        wrong_root_chirho.canonical_root_digest_chirho = "wrong-root-digest-chirho".to_owned();
        assert_refuses_before_fence_chirho(
            &root_fixture_chirho,
            &sign_candidate_chirho(&root_fixture_chirho, &wrong_root_chirho),
            "GeoWriterEraActivationRootRefusedChirho",
        );

        let group_fixture_chirho = activation_fixture_chirho("wrong-group");
        let mut wrong_group_chirho = group_fixture_chirho.candidate_chirho.clone();
        wrong_group_chirho.consistency_group_id_chirho = "root-path-chirho:/wrong".to_owned();
        assert_refuses_before_fence_chirho(
            &group_fixture_chirho,
            &sign_candidate_chirho(&group_fixture_chirho, &wrong_group_chirho),
            "GeoWriterEraActivationGroupRefusedChirho",
        );

        let owner_fixture_chirho = activation_fixture_chirho("wrong-owner");
        let mut wrong_owner_chirho = owner_fixture_chirho.candidate_chirho.clone();
        wrong_owner_chirho.owner_node_id_chirho = "c".repeat(64);
        assert_refuses_before_fence_chirho(
            &owner_fixture_chirho,
            &sign_candidate_chirho(&owner_fixture_chirho, &wrong_owner_chirho),
            "GeoWriterEraActivationOwnerRefusedChirho",
        );

        let roster_fixture_chirho = activation_fixture_chirho("wrong-roster");
        let mut wrong_roster_chirho = roster_fixture_chirho.candidate_chirho.clone();
        wrong_roster_chirho.roster_head_blake3_chirho = "d".repeat(64);
        assert_refuses_before_fence_chirho(
            &roster_fixture_chirho,
            &sign_candidate_chirho(&roster_fixture_chirho, &wrong_roster_chirho),
            "GeoWriterEraActivationRosterRefusedChirho",
        );

        let config_fixture_chirho = activation_fixture_chirho("wrong-config");
        let mut wrong_config_chirho = config_fixture_chirho.candidate_chirho.clone();
        wrong_config_chirho.cluster_config_blake3_chirho = "e".repeat(64);
        assert_refuses_before_fence_chirho(
            &config_fixture_chirho,
            &sign_candidate_chirho(&config_fixture_chirho, &wrong_config_chirho),
            "GeoWriterEraActivationClusterConfigRefusedChirho",
        );
    }

    #[test]
    fn signature_operator_and_window_failures_remain_distinct_chirho() {
        let signature_fixture_chirho = activation_fixture_chirho("bad-signature");
        let mut bad_signature_chirho = sign_candidate_chirho(
            &signature_fixture_chirho,
            &signature_fixture_chirho.candidate_chirho,
        );
        bad_signature_chirho.sig_chirho = "00".repeat(64);
        assert_refuses_before_fence_chirho(
            &signature_fixture_chirho,
            &bad_signature_chirho,
            "GeoWriterEraActivationSignatureRefusedChirho",
        );

        let operator_fixture_chirho = activation_fixture_chirho("wrong-operator");
        let mut wrong_operator_chirho = sign_candidate_chirho(
            &operator_fixture_chirho,
            &operator_fixture_chirho.candidate_chirho,
        );
        wrong_operator_chirho.operator_key_id_chirho = "f".repeat(64);
        assert_refuses_before_fence_chirho(
            &operator_fixture_chirho,
            &wrong_operator_chirho,
            "GeoWriterEraActivationOperatorRefusedChirho",
        );

        let window_fixture_chirho = activation_fixture_chirho("expired-window");
        let expired_chirho = sign_writer_era_activation_candidate_at_chirho(
            &window_fixture_chirho.candidate_chirho,
            &window_fixture_chirho.operator_root_chirho,
            1,
        )
        .expect("sign expired authorization");
        assert_refuses_before_fence_chirho(
            &window_fixture_chirho,
            &expired_chirho,
            "GeoWriterEraActivationWindowRefusedChirho",
        );
    }
}
