// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::model_chirho::{
    decode_and_verify_receipt_chirho, decode_and_verify_view_chirho, validate_source_config_chirho,
    ProjectionReplicationIdentityChirho, ProjectionReplicationSourceConfigChirho,
};
use super::{
    is_lower_hex_64_chirho, MAX_PROJECTION_RECEIPT_BYTES_CHIRHO, MAX_PROJECTION_VIEW_BYTES_CHIRHO,
    PROJECTION_REPLICATION_HEAD_PATH_CHIRHO, PROJECTION_REPLICATION_VIEW_PATH_CHIRHO,
};
use crate::bearer_header_matches_chirho;
use anyhow::{bail, Context, Result};
use axum::{
    extract::{Path as AxumPathChirho, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho;
use cairn_ledger_read_model_chirho::publication_chirho::view_cas_path_chirho;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[derive(Debug)]
struct CurrentProjectionArtifactChirho {
    receipt_bytes_chirho: Vec<u8>,
    view_bytes_chirho: Vec<u8>,
    view_digest_chirho: String,
}

/// One fixed, read-only published-projection coordinate.
///
/// It has no ledger storage port and no signer. Every request reopens the configured receipt and its
/// currently bound view through bounded identity-stable reads, so the source cannot append, repair,
/// publish, or select an arbitrary path on behalf of a peer.
#[derive(Debug)]
pub struct FsProjectionReplicationSourceChirho {
    canonical_namespace_root_chirho: PathBuf,
    head_path_chirho: String,
    identity_chirho: ProjectionReplicationIdentityChirho,
    root_identity_chirho: FilesystemIdentityChirho,
    root_owner_chirho: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FilesystemIdentityChirho {
    device_chirho: u64,
    inode_chirho: u64,
}

impl FsProjectionReplicationSourceChirho {
    pub fn open_existing_chirho(
        config_chirho: &ProjectionReplicationSourceConfigChirho,
    ) -> Result<Self> {
        validate_source_config_chirho(config_chirho)?;
        let configured_metadata_chirho =
            fs::symlink_metadata(&config_chirho.source_namespace_root_chirho)
                .context("ProjectionReplicaSourceRootReadRefusedChirho")?;
        if configured_metadata_chirho.file_type().is_symlink()
            || !configured_metadata_chirho.is_dir()
        {
            bail!("ProjectionReplicaSourceRootTypeRefusedChirho");
        }
        let canonical_namespace_root_chirho = config_chirho
            .source_namespace_root_chirho
            .canonicalize()
            .context("ProjectionReplicaSourceRootCanonicalRefusedChirho")?;
        let canonical_metadata_chirho = fs::metadata(&canonical_namespace_root_chirho)
            .context("ProjectionReplicaSourceRootReadRefusedChirho")?;
        validate_directory_metadata_chirho(&canonical_metadata_chirho, None)?;
        let root_owner_chirho = metadata_owner_chirho(&canonical_metadata_chirho);
        Ok(Self {
            canonical_namespace_root_chirho,
            head_path_chirho: config_chirho.head_path_chirho.clone(),
            identity_chirho: config_chirho.identity_chirho.clone(),
            root_identity_chirho: metadata_identity_chirho(&canonical_metadata_chirho),
            root_owner_chirho,
        })
    }

    fn load_current_projection_chirho(&self) -> Result<CurrentProjectionArtifactChirho> {
        let receipt_bytes_chirho = self
            .read_required_chirho(&self.head_path_chirho, MAX_PROJECTION_RECEIPT_BYTES_CHIRHO)
            .context("ProjectionReplicaSourceHeadReadRefusedChirho")?;
        let receipt_chirho =
            decode_and_verify_receipt_chirho(&receipt_bytes_chirho, &self.identity_chirho)?;
        let view_path_chirho = view_cas_path_chirho(&receipt_chirho.view_digest_hex_chirho).0;
        let view_bytes_chirho = self
            .read_required_chirho(&view_path_chirho, MAX_PROJECTION_VIEW_BYTES_CHIRHO)
            .context("ProjectionReplicaSourceViewReadRefusedChirho")?;
        decode_and_verify_view_chirho(&view_bytes_chirho, &receipt_chirho.view_digest_hex_chirho)?;
        Ok(CurrentProjectionArtifactChirho {
            receipt_bytes_chirho,
            view_bytes_chirho,
            view_digest_chirho: receipt_chirho.view_digest_hex_chirho,
        })
    }

    fn read_required_chirho(
        &self,
        relative_chirho: &str,
        max_bytes_chirho: u64,
    ) -> Result<Vec<u8>> {
        self.verify_root_and_parent_chain_chirho(relative_chirho)?;
        let path_chirho = self.canonical_namespace_root_chirho.join(relative_chirho);
        let metadata_chirho = fs::symlink_metadata(&path_chirho)
            .context("ProjectionReplicaSourceObjectMissingChirho")?;
        validate_regular_metadata_chirho(
            &metadata_chirho,
            self.root_owner_chirho,
            max_bytes_chirho,
        )?;
        read_identity_stable_bounded_regular_file_chirho(&path_chirho, max_bytes_chirho)
            .context("ProjectionReplicaSourceObjectReadRefusedChirho")
    }

    fn verify_root_and_parent_chain_chirho(&self, relative_chirho: &str) -> Result<()> {
        let root_metadata_chirho = fs::metadata(&self.canonical_namespace_root_chirho)
            .context("ProjectionReplicaSourceRootReadRefusedChirho")?;
        validate_directory_metadata_chirho(&root_metadata_chirho, Some(self.root_owner_chirho))?;
        if metadata_identity_chirho(&root_metadata_chirho) != self.root_identity_chirho {
            bail!("ProjectionReplicaSourceRootIdentityRefusedChirho");
        }
        let relative_path_chirho = Path::new(relative_chirho);
        if relative_path_chirho.is_absolute()
            || relative_path_chirho.as_os_str().is_empty()
            || !relative_path_chirho
                .components()
                .all(|component_chirho| matches!(component_chirho, Component::Normal(_)))
        {
            bail!("ProjectionReplicaSourcePathRefusedChirho");
        }
        let mut current_chirho = self.canonical_namespace_root_chirho.clone();
        if let Some(parent_chirho) = relative_path_chirho.parent() {
            for component_chirho in parent_chirho.components() {
                let Component::Normal(component_chirho) = component_chirho else {
                    bail!("ProjectionReplicaSourcePathRefusedChirho");
                };
                current_chirho.push(component_chirho);
                let metadata_chirho = fs::symlink_metadata(&current_chirho)
                    .context("ProjectionReplicaSourceParentReadRefusedChirho")?;
                validate_directory_metadata_chirho(&metadata_chirho, Some(self.root_owner_chirho))?;
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct ProjectionReplicationServerStateChirho {
    source_chirho: Arc<FsProjectionReplicationSourceChirho>,
    bearer_token_chirho: Arc<String>,
}

pub fn projection_replication_router_chirho(
    source_chirho: Arc<FsProjectionReplicationSourceChirho>,
    bearer_token_chirho: String,
) -> Router {
    Router::new()
        .route(
            PROJECTION_REPLICATION_HEAD_PATH_CHIRHO,
            get(get_projection_head_chirho),
        )
        .route(
            PROJECTION_REPLICATION_VIEW_PATH_CHIRHO,
            get(get_projection_view_chirho),
        )
        .with_state(ProjectionReplicationServerStateChirho {
            source_chirho,
            bearer_token_chirho: Arc::new(bearer_token_chirho),
        })
}

pub fn serve_projection_router_blocking_chirho(
    listener_chirho: std::net::TcpListener,
    router_chirho: Router,
) -> Result<()> {
    crate::server_chirho::serve_router_blocking_chirho(listener_chirho, router_chirho)
}

async fn get_projection_head_chirho(
    State(state_chirho): State<ProjectionReplicationServerStateChirho>,
    headers_chirho: HeaderMap,
) -> Response {
    if !request_is_authorized_chirho(&state_chirho, &headers_chirho) {
        return named_response_chirho(
            StatusCode::UNAUTHORIZED,
            "ProjectionReplicaBearerRefusedChirho",
        );
    }
    match state_chirho.source_chirho.load_current_projection_chirho() {
        Ok(current_chirho) => octet_stream_chirho(current_chirho.receipt_bytes_chirho),
        Err(_error_chirho) => named_response_chirho(
            StatusCode::CONFLICT,
            "ProjectionReplicaSourceCurrentReadRefusedChirho",
        ),
    }
}

async fn get_projection_view_chirho(
    State(state_chirho): State<ProjectionReplicationServerStateChirho>,
    headers_chirho: HeaderMap,
    AxumPathChirho(digest_chirho): AxumPathChirho<String>,
) -> Response {
    if !request_is_authorized_chirho(&state_chirho, &headers_chirho) {
        return named_response_chirho(
            StatusCode::UNAUTHORIZED,
            "ProjectionReplicaBearerRefusedChirho",
        );
    }
    if !is_lower_hex_64_chirho(&digest_chirho) {
        return named_response_chirho(
            StatusCode::BAD_REQUEST,
            "ProjectionReplicaViewDigestShapeRefusedChirho",
        );
    }
    match state_chirho.source_chirho.load_current_projection_chirho() {
        Ok(current_chirho) if current_chirho.view_digest_chirho == digest_chirho => {
            octet_stream_chirho(current_chirho.view_bytes_chirho)
        }
        Ok(_current_chirho) => named_response_chirho(
            StatusCode::CONFLICT,
            "ProjectionReplicaViewNotCurrentRefusedChirho",
        ),
        Err(_error_chirho) => named_response_chirho(
            StatusCode::CONFLICT,
            "ProjectionReplicaSourceCurrentReadRefusedChirho",
        ),
    }
}

fn request_is_authorized_chirho(
    state_chirho: &ProjectionReplicationServerStateChirho,
    headers_chirho: &HeaderMap,
) -> bool {
    bearer_header_matches_chirho(
        &state_chirho.bearer_token_chirho,
        headers_chirho
            .get(header::AUTHORIZATION)
            .and_then(|value_chirho| value_chirho.to_str().ok()),
    )
}

fn octet_stream_chirho(bytes_chirho: Vec<u8>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/octet-stream")],
        bytes_chirho,
    )
        .into_response()
}

fn named_response_chirho(status_chirho: StatusCode, refusal_chirho: &'static str) -> Response {
    (
        status_chirho,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        refusal_chirho,
    )
        .into_response()
}

fn validate_directory_metadata_chirho(
    metadata_chirho: &fs::Metadata,
    expected_owner_chirho: Option<u32>,
) -> Result<()> {
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_dir() {
        bail!("ProjectionReplicaSourceDirectoryTypeRefusedChirho");
    }
    #[cfg(unix)]
    {
        if metadata_chirho.mode() & 0o022 != 0
            || expected_owner_chirho
                .is_some_and(|owner_chirho| metadata_chirho.uid() != owner_chirho)
        {
            bail!("ProjectionReplicaSourceDirectoryCustodyRefusedChirho");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = expected_owner_chirho;
    }
    Ok(())
}

fn validate_regular_metadata_chirho(
    metadata_chirho: &fs::Metadata,
    expected_owner_chirho: u32,
    max_bytes_chirho: u64,
) -> Result<()> {
    if metadata_chirho.file_type().is_symlink()
        || !metadata_chirho.is_file()
        || metadata_chirho.len() > max_bytes_chirho
    {
        bail!("ProjectionReplicaSourceObjectTypeRefusedChirho");
    }
    #[cfg(unix)]
    if metadata_chirho.uid() != expected_owner_chirho
        || metadata_chirho.mode() & 0o022 != 0
        || metadata_chirho.nlink() != 1
    {
        bail!("ProjectionReplicaSourceObjectCustodyRefusedChirho");
    }
    #[cfg(not(unix))]
    {
        let _ = expected_owner_chirho;
    }
    Ok(())
}

#[cfg(unix)]
fn metadata_identity_chirho(metadata_chirho: &fs::Metadata) -> FilesystemIdentityChirho {
    FilesystemIdentityChirho {
        device_chirho: metadata_chirho.dev(),
        inode_chirho: metadata_chirho.ino(),
    }
}

#[cfg(not(unix))]
fn metadata_identity_chirho(_metadata_chirho: &fs::Metadata) -> FilesystemIdentityChirho {
    FilesystemIdentityChirho {
        device_chirho: 0,
        inode_chirho: 0,
    }
}

#[cfg(unix)]
fn metadata_owner_chirho(metadata_chirho: &fs::Metadata) -> u32 {
    metadata_chirho.uid()
}

#[cfg(not(unix))]
fn metadata_owner_chirho(_metadata_chirho: &fs::Metadata) -> u32 {
    0
}
