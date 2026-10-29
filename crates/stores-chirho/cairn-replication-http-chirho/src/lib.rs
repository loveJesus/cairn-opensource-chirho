// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Real over-the-wire HTTP transport for the P3 `ReplicationSourceChirho` port: an axum source
//! server that serves ONLY immutable objects (by hash) and allowlisted public logs — enforcing the
//! same `is_replicable_log_name_chirho` allowlist SERVER-SIDE so a hostile replica can never fetch the
//! source's signing key over the wire — plus a `ureq` client adapter that implements the identical
//! read-only port, so the existing receiver hash-verifies every pulled object client-side and the fold
//! verify is reused verbatim. This is the network transport double; a CEPH/S3 object backend swaps in
//! later behind the very same port.

pub mod client_chirho;
pub mod projection_replication_chirho;
pub mod read_dag_chirho;

pub use read_dag_chirho::{
    ReplicaBalancePageViewChirho, ReplicaBalanceReadDagChirho, ReplicaBalanceReadDagRunnerChirho,
    ReplicaReadDagRefusalChirho, BALANCE_DAG_OUTPUT_CAP_CHIRHO, BALANCE_QUERY_LIMIT_CHIRHO,
    BALANCE_QUERY_SCOPE_CHIRHO,
};
pub mod pull_chirho;
pub mod server_chirho;

#[cfg(test)]
mod pure_tests_chirho;

/// The route prefix for every replication endpoint.
pub const REPLICATION_ROUTE_PREFIX_CHIRHO: &str = "/replication-chirho";
/// The object-list route (returns a JSON array of content-address hex strings).
pub const REPLICATION_OBJECTS_LIST_PATH_CHIRHO: &str = "/replication-chirho/objects-chirho";
/// The single-object route (axum 0.7 colon syntax); the param is a 64-lowercase-hex content address.
pub const REPLICATION_OBJECT_BY_HASH_PATH_CHIRHO: &str =
    "/replication-chirho/objects-chirho/:hash_chirho";
/// The named-log route (axum 0.7 colon syntax); the param must pass the public-log allowlist.
pub const REPLICATION_LOG_BY_NAME_PATH_CHIRHO: &str =
    "/replication-chirho/logs-chirho/:name_chirho";

/// Build the object-list URL against a base like `http://127.0.0.1:8080`.
pub fn objects_list_url_chirho(base_chirho: &str) -> String {
    format!(
        "{}{}",
        base_chirho.trim_end_matches('/'),
        REPLICATION_OBJECTS_LIST_PATH_CHIRHO
    )
}

/// Build the single-object URL for a content address.
pub fn object_by_hash_url_chirho(base_chirho: &str, hash_chirho: &str) -> String {
    format!(
        "{}{}/{}",
        base_chirho.trim_end_matches('/'),
        REPLICATION_OBJECTS_LIST_PATH_CHIRHO,
        hash_chirho
    )
}

/// Build the named-log URL.
pub fn log_by_name_url_chirho(base_chirho: &str, name_chirho: &str) -> String {
    format!(
        "{}{}/logs-chirho/{}",
        base_chirho.trim_end_matches('/'),
        REPLICATION_ROUTE_PREFIX_CHIRHO,
        name_chirho
    )
}

/// A content address on the wire must be exactly 64 lowercase hex characters — validated before any
/// filesystem/store touch so a route parameter can never be a path or an oversized key.
pub fn is_valid_object_hash_chirho(hash_chirho: &str) -> bool {
    hash_chirho.len() == 64
        && hash_chirho
            .bytes()
            .all(|b_chirho| b_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&b_chirho))
}

/// Resolve a bearer token from the ENV VAR a config names, fail-closed: naming a var that is unset
/// or blank is an error, so a deployment typo can never silently serve (or pull) unauthenticated.
/// `None` (no var named) is the explicit trusted-network / loopback choice. Config files carry only
/// the var NAME; the secret itself never lives in a config file. Used by both reference binaries.
pub fn resolve_bearer_from_env_chirho(
    bearer_env_chirho: Option<&str>,
) -> anyhow::Result<Option<String>> {
    use anyhow::{anyhow, bail};
    match bearer_env_chirho {
        None => Ok(None),
        Some(var_chirho) => {
            let value_chirho = std::env::var(var_chirho).map_err(|_| {
                anyhow!("bearer env var {var_chirho} is named in config but not set")
            })?;
            if value_chirho.trim().is_empty() {
                bail!("bearer env var {var_chirho} is set but empty");
            }
            Ok(Some(value_chirho))
        }
    }
}

/// Constant-time byte equality for the bearer token — never leaks length-beyond-mismatch timing. The
/// repo's existing dashboard token compare is a plain `!=`; replication uses this instead.
pub fn constant_time_eq_chirho(a_chirho: &[u8], b_chirho: &[u8]) -> bool {
    if a_chirho.len() != b_chirho.len() {
        return false;
    }
    let mut diff_chirho: u8 = 0;
    for (x_chirho, y_chirho) in a_chirho.iter().zip(b_chirho.iter()) {
        diff_chirho |= x_chirho ^ y_chirho;
    }
    diff_chirho == 0
}

/// Check one optional `Authorization` value against a required bearer without copying either token.
///
/// This stays transport-only: it authenticates the puller but grants no filesystem coordinate.
pub fn bearer_header_matches_chirho(
    expected_chirho: &str,
    provided_header_chirho: Option<&str>,
) -> bool {
    provided_header_chirho
        .and_then(|header_chirho| header_chirho.strip_prefix("Bearer "))
        .is_some_and(|provided_chirho| {
            constant_time_eq_chirho(provided_chirho.as_bytes(), expected_chirho.as_bytes())
        })
}
