// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Mesh-bound read-only source for one configured feeder-signed account-net projection.

use anyhow::{anyhow, Context, Result};
use cairn_replication_http_chirho::projection_replication_chirho::{
    projection_replication_router_chirho, serve_projection_router_blocking_chirho,
    FsProjectionReplicationSourceChirho, ProjectionReplicationSourceConfigChirho,
};
use cairn_replication_http_chirho::resolve_bearer_from_env_chirho;
use std::sync::Arc;

fn main() -> Result<()> {
    let config_path_chirho = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: projection_replication_source_chirho <config.json>"))?;
    let config_bytes_chirho = std::fs::read(&config_path_chirho).with_context(|| {
        format!("ProjectionReplicaConfigReadRefusedChirho:{config_path_chirho}")
    })?;
    let config_chirho: ProjectionReplicationSourceConfigChirho =
        serde_json::from_slice(&config_bytes_chirho)
            .context("ProjectionReplicaConfigParseRefusedChirho")?;
    let source_chirho = Arc::new(FsProjectionReplicationSourceChirho::open_existing_chirho(
        &config_chirho,
    )?);
    let bearer_chirho = resolve_bearer_from_env_chirho(Some(&config_chirho.bearer_env_chirho))
        .context("ProjectionReplicaBearerRefusedChirho")?
        .ok_or_else(|| anyhow!("ProjectionReplicaBearerRefusedChirho"))?;
    let listener_chirho = std::net::TcpListener::bind(&config_chirho.listen_addr_chirho)
        .with_context(|| {
            format!(
                "ProjectionReplicaListenRefusedChirho:{}",
                config_chirho.listen_addr_chirho
            )
        })?;
    let router_chirho = projection_replication_router_chirho(source_chirho, bearer_chirho);
    serve_projection_router_blocking_chirho(listener_chirho, router_chirho)
}
