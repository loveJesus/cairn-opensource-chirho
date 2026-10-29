// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! B2.6 reference replica server. It re-verifies the operator roster and signed ref snapshot on
//! every start, then binds only loopback/private/mesh addresses unless a separate explicit public
//! approval is represented by `allow_public_bind_chirho: true`.

use anyhow::{anyhow, Context, Result};
use cairn_replica_serve_http_chirho::composition_chirho::{
    load_verified_replica_serve_chirho, ReplicaServeConfigChirho,
};
use cairn_replica_serve_http_chirho::{
    bind_replica_listener_chirho, replica_serve_router_chirho, serve_replica_blocking_chirho,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<()> {
    let config_path_chirho = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: replica_serve_chirho <config.json>"))?;
    let config_bytes_chirho = std::fs::read(&config_path_chirho)
        .with_context(|| format!("ReplicaServeConfigReadRefusedChirho:{config_path_chirho}"))?;
    let config_chirho: ReplicaServeConfigChirho = serde_json::from_slice(&config_bytes_chirho)
        .context("ReplicaServeConfigParseRefusedChirho")?;
    let verified_at_unix_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("ReplicaServeClockRefusedChirho")?
        .as_secs();
    let prepared_chirho =
        load_verified_replica_serve_chirho(&config_chirho, verified_at_unix_chirho)?;
    let listener_chirho = bind_replica_listener_chirho(
        &config_chirho.listen_addr_chirho,
        config_chirho.allow_public_bind_chirho,
    )
    .context("ReplicaServeBindRefusedChirho")?;
    println!(
        "{}",
        serde_json::json!({
            "schema_chirho": "replica-serve-start-v1-chirho",
            "listen_addr_chirho": config_chirho.listen_addr_chirho,
            "source_region_chirho": prepared_chirho.source_region_chirho,
            "snapshot_seq_chirho": prepared_chirho.mount_report_chirho.seq_chirho,
            "source_time_unix_chirho": prepared_chirho.mount_report_chirho.source_time_unix_chirho,
            "verified_at_unix_chirho": prepared_chirho.mount_report_chirho.verified_at_unix_chirho,
            "ref_count_chirho": prepared_chirho.mount_report_chirho.ref_count_chirho,
            "decision_chirho": prepared_chirho.mount_report_chirho.decision_chirho,
            "public_bind_approved_chirho": config_chirho.allow_public_bind_chirho,
        })
    );
    let router_chirho = replica_serve_router_chirho(prepared_chirho.state_chirho);
    serve_replica_blocking_chirho(listener_chirho, router_chirho)
        .context("ReplicaServeRuntimeRefusedChirho")
}
