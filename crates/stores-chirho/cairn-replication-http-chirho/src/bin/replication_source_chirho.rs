// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Reference deployable replication SOURCE server: serves one store root's immutable objects and
//! allowlisted public logs over HTTP, read-only — a replica can be handed nothing that advances a
//! head. The JSON config names the served root, the bind address (bind the private-mesh IP, never
//! 0.0.0.0), and optionally the ENV VAR holding the bearer token, so the config file itself never
//! carries the secret. Part of the distributed-HA P3 workflow
//! (`spec-chirho/workflows-chirho/distributed-ha-chirho/`).

use anyhow::{anyhow, bail, Context, Result};
use cairn_replication_chirho::ReplicationSourceChirho;
use cairn_replication_http_chirho::resolve_bearer_from_env_chirho;
use cairn_replication_http_chirho::server_chirho::{
    replication_router_chirho, serve_router_blocking_chirho,
};
use cairn_replication_localfs_chirho::LocalFsReplicationSourceChirho;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Deserialize)]
struct SourceConfigChirho {
    /// The store root whose objects and allowlisted logs are served.
    root_chirho: PathBuf,
    /// Bind address, e.g. `10.100.0.1:8400` — the private mesh IP, never a public interface.
    listen_addr_chirho: String,
    /// Optional NAME of the env var holding the bearer token (the value never lives in config).
    #[serde(default)]
    bearer_env_chirho: Option<String>,
}

fn main() -> Result<()> {
    let config_path_chirho = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: replication_source_chirho <config.json>"))?;
    let config_bytes_chirho = std::fs::read(&config_path_chirho)
        .with_context(|| format!("read config {config_path_chirho}"))?;
    let config_chirho: SourceConfigChirho =
        serde_json::from_slice(&config_bytes_chirho).context("parse source config JSON")?;

    if !config_chirho.root_chirho.is_dir() {
        bail!(
            "served root {} is not a directory",
            config_chirho.root_chirho.display()
        );
    }
    let bearer_chirho = resolve_bearer_from_env_chirho(config_chirho.bearer_env_chirho.as_deref())?;

    let listener_chirho = std::net::TcpListener::bind(&config_chirho.listen_addr_chirho)
        .with_context(|| format!("bind {}", config_chirho.listen_addr_chirho))?;
    println!(
        "replication source: root {} on {} (bearer {})",
        config_chirho.root_chirho.display(),
        config_chirho.listen_addr_chirho,
        if bearer_chirho.is_some() {
            "REQUIRED"
        } else {
            "OPEN — trusted network only"
        },
    );
    let source_chirho: Arc<dyn ReplicationSourceChirho + Send + Sync> = Arc::new(
        LocalFsReplicationSourceChirho::new_chirho(&config_chirho.root_chirho),
    );
    let router_chirho = replication_router_chirho(source_chirho, bearer_chirho);
    serve_router_blocking_chirho(listener_chirho, router_chirho)
}
