// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::model_chirho::{
    decode_and_verify_receipt_chirho, decode_and_verify_view_chirho, validate_pull_config_chirho,
    ProjectionReplicaAccountObservationChirho, ProjectionReplicaMountChirho,
    ProjectionReplicaPullConfigChirho, ProjectionReplicaPullDispositionChirho,
    ProjectionReplicaPullReportChirho, PROJECTION_REPLICA_MOUNT_SCHEMA_V1_CHIRHO,
    PROJECTION_REPLICA_PULL_REPORT_SCHEMA_V1_CHIRHO,
};
use super::{
    projection_head_url_chirho, projection_view_url_chirho, MAX_PROJECTION_RECEIPT_BYTES_CHIRHO,
    MAX_PROJECTION_VIEW_BYTES_CHIRHO,
};
use crate::resolve_bearer_from_env_chirho;
use anyhow::{bail, Context, Result};
use cairn_durable_chirho::{
    create_file_durable_chirho, read_identity_stable_bounded_regular_file_chirho,
    write_file_durable_chirho, CreateFileDurableOutcomeChirho,
};
use cairn_ledger_read_model_chirho::account_net_chirho::AccountNetProjectionViewChirho;
use cairn_ledger_read_model_chirho::feeder_chirho::FollowReceiptChirho;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const PROJECTION_REPLICA_DIR_CHIRHO: &str = "projection-replica-chirho";
const PROJECTION_REPLICA_VIEWS_DIR_CHIRHO: &str = "views-chirho";
const PROJECTION_REPLICA_MOUNT_FILE_CHIRHO: &str = "mounted-projection-chirho.json";
const MAX_PROJECTION_MOUNT_BYTES_CHIRHO: u64 = 512 * 1024;
const MAX_NAMED_HTTP_REFUSAL_BYTES_CHIRHO: u64 = 4 * 1024;

pub fn mounted_projection_path_chirho(replica_root_chirho: &Path) -> PathBuf {
    replica_root_chirho
        .join(PROJECTION_REPLICA_DIR_CHIRHO)
        .join(PROJECTION_REPLICA_MOUNT_FILE_CHIRHO)
}

fn mounted_view_path_chirho(replica_root_chirho: &Path, digest_chirho: &str) -> PathBuf {
    replica_root_chirho
        .join(PROJECTION_REPLICA_DIR_CHIRHO)
        .join(PROJECTION_REPLICA_VIEWS_DIR_CHIRHO)
        .join(digest_chirho)
}

pub fn pull_and_mount_projection_chirho(
    config_chirho: &ProjectionReplicaPullConfigChirho,
    observed_at_unix_chirho: u64,
) -> Result<ProjectionReplicaPullReportChirho> {
    validate_pull_config_chirho(config_chirho)?;
    let prior_chirho = read_optional_verified_mount_chirho(config_chirho)?;
    let bearer_chirho = resolve_bearer_from_env_chirho(Some(&config_chirho.bearer_env_chirho))
        .context("ProjectionReplicaBearerRefusedChirho")?
        .ok_or_else(|| anyhow::anyhow!("ProjectionReplicaBearerRefusedChirho"))?;
    let client_chirho = HttpProjectionReplicationClientChirho::new_chirho(
        &config_chirho.source_url_chirho,
        bearer_chirho,
    );

    let receipt_bytes_chirho = client_chirho.get_required_chirho(
        &projection_head_url_chirho(&config_chirho.source_url_chirho),
        MAX_PROJECTION_RECEIPT_BYTES_CHIRHO,
        "ProjectionReplicaHeadFetchRefusedChirho",
    )?;
    let receipt_chirho =
        decode_and_verify_receipt_chirho(&receipt_bytes_chirho, &config_chirho.identity_chirho)?;
    let disposition_chirho = classify_receipt_advance_chirho(
        prior_chirho
            .as_ref()
            .map(|(mount_chirho, _view_chirho)| &mount_chirho.receipt_chirho),
        &receipt_chirho,
    )?;

    let view_bytes_chirho = client_chirho.get_required_chirho(
        &projection_view_url_chirho(
            &config_chirho.source_url_chirho,
            &receipt_chirho.view_digest_hex_chirho,
        ),
        MAX_PROJECTION_VIEW_BYTES_CHIRHO,
        "ProjectionReplicaViewFetchRefusedChirho",
    )?;
    let view_chirho =
        decode_and_verify_view_chirho(&view_bytes_chirho, &receipt_chirho.view_digest_hex_chirho)?;
    let inspected_accounts_chirho = inspect_accounts_chirho(config_chirho, &view_chirho)?;

    if disposition_chirho != ProjectionReplicaPullDispositionChirho::AlreadyCurrentChirho {
        prepare_replica_directories_chirho(&config_chirho.replica_root_chirho)?;
        install_view_chirho(
            &config_chirho.replica_root_chirho,
            &receipt_chirho.view_digest_hex_chirho,
            &view_bytes_chirho,
        )?;
        let mount_chirho = ProjectionReplicaMountChirho {
            schema_chirho: PROJECTION_REPLICA_MOUNT_SCHEMA_V1_CHIRHO.to_owned(),
            identity_chirho: config_chirho.identity_chirho.clone(),
            mounted_at_unix_chirho: observed_at_unix_chirho,
            receipt_chirho: receipt_chirho.clone(),
        };
        let mount_bytes_chirho = serde_json::to_vec(&mount_chirho)
            .context("ProjectionReplicaMountEncodeRefusedChirho")?;
        write_file_durable_chirho(
            &mounted_projection_path_chirho(&config_chirho.replica_root_chirho),
            &mount_bytes_chirho,
        )
        .context("ProjectionReplicaMountWriteRefusedChirho")?;
    }

    Ok(ProjectionReplicaPullReportChirho {
        schema_chirho: PROJECTION_REPLICA_PULL_REPORT_SCHEMA_V1_CHIRHO.to_owned(),
        disposition_chirho,
        observed_at_unix_chirho,
        source_tail_seq_chirho: receipt_chirho.source_tail_seq_chirho,
        source_tail_line_digest_chirho: receipt_chirho.source_tail_line_digest_chirho.0,
        view_digest_hex_chirho: receipt_chirho.view_digest_hex_chirho,
        view_rows_chirho: u64::try_from(view_chirho.rows_chirho.len())
            .context("ProjectionReplicaViewPopulationRefusedChirho")?,
        inspected_accounts_chirho,
    })
}

pub fn read_verified_mounted_projection_chirho(
    config_chirho: &ProjectionReplicaPullConfigChirho,
) -> Result<(ProjectionReplicaMountChirho, AccountNetProjectionViewChirho)> {
    validate_pull_config_chirho(config_chirho)?;
    read_optional_verified_mount_chirho(config_chirho)?
        .ok_or_else(|| anyhow::anyhow!("ProjectionReplicaMountMissingChirho"))
}

fn read_optional_verified_mount_chirho(
    config_chirho: &ProjectionReplicaPullConfigChirho,
) -> Result<Option<(ProjectionReplicaMountChirho, AccountNetProjectionViewChirho)>> {
    let mount_path_chirho = mounted_projection_path_chirho(&config_chirho.replica_root_chirho);
    let replica_owner_chirho = match fs::symlink_metadata(&config_chirho.replica_root_chirho) {
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None)
        }
        Err(error_chirho) => {
            return Err(error_chirho).context("ProjectionReplicaRootReadRefusedChirho")
        }
        Ok(metadata_chirho) => validate_replica_directory_metadata_chirho(&metadata_chirho, None)?,
    };
    match fs::symlink_metadata(&mount_path_chirho) {
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None)
        }
        Err(error_chirho) => {
            return Err(error_chirho).context("ProjectionReplicaMountReadRefusedChirho")
        }
        Ok(metadata_chirho) => validate_replica_file_metadata_chirho(
            &metadata_chirho,
            replica_owner_chirho,
            MAX_PROJECTION_MOUNT_BYTES_CHIRHO,
        )?,
    }
    let mount_bytes_chirho = read_identity_stable_bounded_regular_file_chirho(
        &mount_path_chirho,
        MAX_PROJECTION_MOUNT_BYTES_CHIRHO,
    )
    .context("ProjectionReplicaMountReadRefusedChirho")?;
    let mount_chirho: ProjectionReplicaMountChirho = serde_json::from_slice(&mount_bytes_chirho)
        .context("ProjectionReplicaMountDecodeRefusedChirho")?;
    if serde_json::to_vec(&mount_chirho).context("ProjectionReplicaMountEncodeRefusedChirho")?
        != mount_bytes_chirho
    {
        bail!("ProjectionReplicaMountCanonicalRefusedChirho");
    }
    if mount_chirho.schema_chirho != PROJECTION_REPLICA_MOUNT_SCHEMA_V1_CHIRHO {
        bail!("ProjectionReplicaMountSchemaRefusedChirho");
    }
    if mount_chirho.identity_chirho != config_chirho.identity_chirho {
        bail!("ProjectionReplicaMountIdentityRefusedChirho");
    }
    let canonical_receipt_bytes_chirho = serde_json::to_vec(&mount_chirho.receipt_chirho)
        .context("ProjectionReplicaReceiptEncodeRefusedChirho")?;
    let verified_receipt_chirho = decode_and_verify_receipt_chirho(
        &canonical_receipt_bytes_chirho,
        &config_chirho.identity_chirho,
    )?;
    let view_path_chirho = mounted_view_path_chirho(
        &config_chirho.replica_root_chirho,
        &verified_receipt_chirho.view_digest_hex_chirho,
    );
    let view_metadata_chirho = fs::symlink_metadata(&view_path_chirho)
        .context("ProjectionReplicaMountedViewMissingChirho")?;
    validate_replica_file_metadata_chirho(
        &view_metadata_chirho,
        replica_owner_chirho,
        MAX_PROJECTION_VIEW_BYTES_CHIRHO,
    )?;
    let view_bytes_chirho = read_identity_stable_bounded_regular_file_chirho(
        &view_path_chirho,
        MAX_PROJECTION_VIEW_BYTES_CHIRHO,
    )
    .context("ProjectionReplicaMountedViewReadRefusedChirho")?;
    let view_chirho = decode_and_verify_view_chirho(
        &view_bytes_chirho,
        &verified_receipt_chirho.view_digest_hex_chirho,
    )?;
    Ok(Some((mount_chirho, view_chirho)))
}

pub(super) fn classify_receipt_advance_chirho(
    prior_chirho: Option<&FollowReceiptChirho>,
    next_chirho: &FollowReceiptChirho,
) -> Result<ProjectionReplicaPullDispositionChirho> {
    let Some(prior_chirho) = prior_chirho else {
        return Ok(ProjectionReplicaPullDispositionChirho::InstalledInitialChirho);
    };
    if next_chirho.source_tail_seq_chirho < prior_chirho.source_tail_seq_chirho {
        bail!("ProjectionReplicaRollbackRefusedChirho");
    }
    if next_chirho.source_tail_seq_chirho == prior_chirho.source_tail_seq_chirho {
        if next_chirho != prior_chirho {
            bail!("ProjectionReplicaSameSequenceEquivocationRefusedChirho");
        }
        return Ok(ProjectionReplicaPullDispositionChirho::AlreadyCurrentChirho);
    }
    if next_chirho.source_tail_hlc_chirho < prior_chirho.source_tail_hlc_chirho {
        bail!("ProjectionReplicaSourceClockRegressionRefusedChirho");
    }
    if next_chirho.source_tail_line_digest_chirho == prior_chirho.source_tail_line_digest_chirho {
        bail!("ProjectionReplicaSourceTailDidNotAdvanceRefusedChirho");
    }
    Ok(ProjectionReplicaPullDispositionChirho::AdvancedChirho)
}

fn inspect_accounts_chirho(
    config_chirho: &ProjectionReplicaPullConfigChirho,
    view_chirho: &AccountNetProjectionViewChirho,
) -> Result<Vec<ProjectionReplicaAccountObservationChirho>> {
    config_chirho
        .inspect_accounts_chirho
        .iter()
        .map(|account_chirho| {
            let index_chirho = view_chirho
                .rows_chirho
                .binary_search_by(|row_chirho| row_chirho.account_chirho.cmp(account_chirho))
                .map_err(|_error_chirho| {
                    anyhow::anyhow!("ProjectionReplicaInspectedAccountMissingChirho")
                })?;
            Ok(ProjectionReplicaAccountObservationChirho {
                account_chirho: account_chirho.clone(),
                account_net_chirho: view_chirho.rows_chirho[index_chirho].account_net_chirho,
            })
        })
        .collect()
}

fn prepare_replica_directories_chirho(replica_root_chirho: &Path) -> Result<()> {
    let replica_owner_chirho = if replica_root_chirho.exists() {
        validate_existing_replica_root_chirho(replica_root_chirho)?
    } else {
        fs::create_dir_all(replica_root_chirho)
            .context("ProjectionReplicaRootCreateRefusedChirho")?;
        validate_existing_replica_root_chirho(replica_root_chirho)?
    };
    let replica_dir_chirho = replica_root_chirho.join(PROJECTION_REPLICA_DIR_CHIRHO);
    let views_dir_chirho = replica_dir_chirho.join(PROJECTION_REPLICA_VIEWS_DIR_CHIRHO);
    fs::create_dir_all(&views_dir_chirho)
        .context("ProjectionReplicaDirectoryCreateRefusedChirho")?;
    validate_replica_directory_metadata_chirho(
        &fs::symlink_metadata(&replica_dir_chirho)
            .context("ProjectionReplicaDirectoryReadRefusedChirho")?,
        Some(replica_owner_chirho),
    )?;
    validate_replica_directory_metadata_chirho(
        &fs::symlink_metadata(&views_dir_chirho)
            .context("ProjectionReplicaDirectoryReadRefusedChirho")?,
        Some(replica_owner_chirho),
    )?;
    Ok(())
}

fn validate_existing_replica_root_chirho(replica_root_chirho: &Path) -> Result<u32> {
    let metadata_chirho = fs::symlink_metadata(replica_root_chirho)
        .context("ProjectionReplicaRootReadRefusedChirho")?;
    validate_replica_directory_metadata_chirho(&metadata_chirho, None)
}

fn validate_replica_directory_metadata_chirho(
    metadata_chirho: &fs::Metadata,
    expected_owner_chirho: Option<u32>,
) -> Result<u32> {
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_dir() {
        bail!("ProjectionReplicaDirectoryTypeRefusedChirho");
    }
    #[cfg(unix)]
    {
        if metadata_chirho.mode() & 0o022 != 0
            || expected_owner_chirho
                .is_some_and(|owner_chirho| metadata_chirho.uid() != owner_chirho)
        {
            bail!("ProjectionReplicaDirectoryCustodyRefusedChirho");
        }
        Ok(metadata_chirho.uid())
    }
    #[cfg(not(unix))]
    {
        let _ = expected_owner_chirho;
        Ok(0)
    }
}

fn validate_replica_file_metadata_chirho(
    metadata_chirho: &fs::Metadata,
    expected_owner_chirho: u32,
    max_bytes_chirho: u64,
) -> Result<()> {
    if metadata_chirho.file_type().is_symlink()
        || !metadata_chirho.is_file()
        || metadata_chirho.len() > max_bytes_chirho
    {
        bail!("ProjectionReplicaFileTypeRefusedChirho");
    }
    #[cfg(unix)]
    if metadata_chirho.uid() != expected_owner_chirho
        || metadata_chirho.mode() & 0o022 != 0
        || metadata_chirho.nlink() != 1
    {
        bail!("ProjectionReplicaFileCustodyRefusedChirho");
    }
    #[cfg(not(unix))]
    {
        let _ = expected_owner_chirho;
    }
    Ok(())
}

fn install_view_chirho(
    replica_root_chirho: &Path,
    digest_chirho: &str,
    bytes_chirho: &[u8],
) -> Result<()> {
    let view_path_chirho = mounted_view_path_chirho(replica_root_chirho, digest_chirho);
    let replica_owner_chirho = validate_existing_replica_root_chirho(replica_root_chirho)?;
    match create_file_durable_chirho(&view_path_chirho, bytes_chirho)
        .context("ProjectionReplicaViewWriteRefusedChirho")?
    {
        CreateFileDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateFileDurableOutcomeChirho::AlreadyExistsChirho => {
            validate_replica_file_metadata_chirho(
                &fs::symlink_metadata(&view_path_chirho)
                    .context("ProjectionReplicaExistingViewReadRefusedChirho")?,
                replica_owner_chirho,
                MAX_PROJECTION_VIEW_BYTES_CHIRHO,
            )?;
            let existing_chirho = read_identity_stable_bounded_regular_file_chirho(
                &view_path_chirho,
                MAX_PROJECTION_VIEW_BYTES_CHIRHO,
            )
            .context("ProjectionReplicaExistingViewReadRefusedChirho")?;
            if existing_chirho != bytes_chirho {
                bail!("ProjectionReplicaExistingViewDivergenceRefusedChirho");
            }
            Ok(())
        }
    }
}

struct HttpProjectionReplicationClientChirho {
    bearer_token_chirho: String,
    agent_chirho: ureq::Agent,
}

impl HttpProjectionReplicationClientChirho {
    fn new_chirho(_source_url_chirho: &str, bearer_token_chirho: String) -> Self {
        Self {
            bearer_token_chirho,
            agent_chirho: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .redirects(0)
                .build(),
        }
    }

    fn get_required_chirho(
        &self,
        url_chirho: &str,
        max_bytes_chirho: u64,
        refusal_chirho: &'static str,
    ) -> Result<Vec<u8>> {
        match self
            .agent_chirho
            .get(url_chirho)
            .set(
                "Authorization",
                &format!("Bearer {}", self.bearer_token_chirho),
            )
            .call()
        {
            Ok(response_chirho) if response_chirho.status() == 200 => {
                read_capped_response_chirho(response_chirho, max_bytes_chirho, refusal_chirho)
            }
            Ok(response_chirho) => {
                let status_chirho = response_chirho.status();
                let body_chirho = read_named_refusal_body_chirho(response_chirho);
                bail!("{refusal_chirho}: status {status_chirho}: {body_chirho}");
            }
            Err(ureq::Error::Status(status_chirho, response_chirho)) => {
                let body_chirho = read_named_refusal_body_chirho(response_chirho);
                bail!("{refusal_chirho}: status {status_chirho}: {body_chirho}");
            }
            Err(error_chirho) => Err(anyhow::anyhow!("{refusal_chirho}: {error_chirho}")),
        }
    }
}

fn read_capped_response_chirho(
    response_chirho: ureq::Response,
    max_bytes_chirho: u64,
    refusal_chirho: &'static str,
) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes_chirho = Vec::new();
    response_chirho
        .into_reader()
        .take(max_bytes_chirho.saturating_add(1))
        .read_to_end(&mut bytes_chirho)
        .with_context(|| refusal_chirho)?;
    if bytes_chirho.len() as u64 > max_bytes_chirho {
        bail!("{refusal_chirho}: response exceeds byte cap");
    }
    Ok(bytes_chirho)
}

fn read_named_refusal_body_chirho(response_chirho: ureq::Response) -> String {
    read_capped_response_chirho(
        response_chirho,
        MAX_NAMED_HTTP_REFUSAL_BYTES_CHIRHO,
        "ProjectionReplicaRefusalBodyReadRefusedChirho",
    )
    .ok()
    .and_then(|bytes_chirho| String::from_utf8(bytes_chirho).ok())
    .unwrap_or_else(|| "ProjectionReplicaRemoteRefusedChirho".to_owned())
}
