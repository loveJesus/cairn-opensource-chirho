// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Read-only transport and verified replica mount for one feeder-signed account-net projection.
//!
//! This is the R2-4 eventual-readback plane. The authoritative owner already publishes the view and
//! signed follow receipt as part of its write path. The source serves that fixed pair without
//! mutation; the replica independently verifies its configured identity, signature, canonical
//! bytes, digest, and monotonic source cut before replacing a derived local mount.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/serve-write-forwarding-design-chirho.md`

mod model_chirho;
mod pull_chirho;
mod replica_read_chirho;
mod source_chirho;

pub use model_chirho::{
    ProjectionReplicaAccountObservationChirho, ProjectionReplicaMountChirho,
    ProjectionReplicaPullConfigChirho, ProjectionReplicaPullDispositionChirho,
    ProjectionReplicaPullReportChirho, ProjectionReplicationIdentityChirho,
    ProjectionReplicationSourceConfigChirho, PROJECTION_REPLICA_MOUNT_SCHEMA_V1_CHIRHO,
    PROJECTION_REPLICA_PULL_REPORT_SCHEMA_V1_CHIRHO,
};
pub use pull_chirho::{
    mounted_projection_path_chirho, pull_and_mount_projection_chirho,
    read_verified_mounted_projection_chirho,
};
pub use replica_read_chirho::{
    ReplicaMountedProjectionReadChirho, ReplicaMountedProjectionReadPortChirho,
    ReplicaProjectionMountCoordinateChirho,
};
pub use source_chirho::{
    projection_replication_router_chirho, serve_projection_router_blocking_chirho,
    FsProjectionReplicationSourceChirho,
};

pub const PROJECTION_REPLICATION_HEAD_PATH_CHIRHO: &str =
    "/replication-chirho/projection-chirho/head-chirho";
pub const PROJECTION_REPLICATION_VIEW_PATH_CHIRHO: &str =
    "/replication-chirho/projection-chirho/view-chirho/:digest_chirho";
pub const MAX_PROJECTION_RECEIPT_BYTES_CHIRHO: u64 = 128 * 1024;
pub const MAX_PROJECTION_VIEW_BYTES_CHIRHO: u64 = 64 * 1024 * 1024;

pub fn projection_head_url_chirho(base_chirho: &str) -> String {
    format!(
        "{}{}",
        base_chirho.trim_end_matches('/'),
        PROJECTION_REPLICATION_HEAD_PATH_CHIRHO
    )
}

pub fn projection_view_url_chirho(base_chirho: &str, digest_chirho: &str) -> String {
    format!(
        "{}/replication-chirho/projection-chirho/view-chirho/{digest_chirho}",
        base_chirho.trim_end_matches('/')
    )
}

pub(crate) fn is_lower_hex_64_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

#[cfg(test)]
mod tests_chirho;
