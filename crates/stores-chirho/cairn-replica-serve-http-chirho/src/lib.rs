// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! GET-only replica artifact serving (B2.1): deliver the M150 public runtime-package contract —
//! capability-free, executable-only, by package hash — from a VERIFIED replica store, with the
//! mounted ref-snapshot view as the discovery/staleness surface. Zero execution, zero effects,
//! no request-body path, no head access: the state holds only a verified store handle plus the
//! read-only `ReplicaRefsViewChirho`, so pre-commitment (a) is structural. Pre-commitment (e):
//! bind through `bind_replica_listener_chirho`, which allows ONLY loopback and private/mesh
//! addresses unless the caller explicitly opts into public exposure (a separate L.J. approval).
//! Design:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/b2-replica-serve-design-chirho.md`.
//!
//! Honest trust scope: the pure public-artifact gate and byte integrity are enforced HERE on
//! every request; deep module/DAG cross-validation happened at primary deploy time and is not
//! re-derived on a replica (that would require root authority a replica must not hold).

use axum::extract::{Path as AxumPathChirho, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::ContentReadChirho;
use cairn_model_runtime_chirho::{
    ensure_public_runtime_package_artifact_chirho, RuntimePackageChirho,
};
use cairn_replication_chirho::ref_snapshot_chirho::{
    RefSnapshotMountReportChirho, ReplicaRefsViewChirho,
};
use cairn_replication_http_chirho::{
    ReplicaBalanceReadDagChirho, ReplicaBalanceReadDagRunnerChirho,
};
use cairn_store_fs_chirho::FsContentStoreChirho;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

pub mod composition_chirho;

/// Everything a replica serves from: the verified store, the mounted read-only view, and the
/// mount's staleness evidence. Deliberately no refs handle, no signer, no writer of any kind.
pub struct ReplicaServeStateChirho {
    /// READ-ONLY BY TYPE. Erased to the read port so the whole serve surface — including the
    /// balance route's read-DAG chain — cannot name `put_chirho`. The composition root may hold a
    /// concrete Fs adapter to verify/mount, but it hands ownership across this boundary and the
    /// live state keeps no wide alias.
    store_chirho: Arc<dyn ContentReadChirho + Send + Sync>,
    view_chirho: ReplicaRefsViewChirho,
    report_chirho: RefSnapshotMountReportChirho,
    balance_read_chirho: Option<Arc<ReplicaBalanceServeBindingChirho>>,
}

/// Explicit R-3 route wiring. The binding owns only the fixed R-2 runner and authored plan;
/// it has no generic effect registry and no writer authority.
pub struct ReplicaBalanceServeBindingChirho {
    runner_chirho: ReplicaBalanceReadDagRunnerChirho,
    dag_chirho: ReplicaBalanceReadDagChirho,
}

impl ReplicaServeStateChirho {
    pub fn new_chirho(
        store_chirho: FsContentStoreChirho,
        view_chirho: ReplicaRefsViewChirho,
        report_chirho: RefSnapshotMountReportChirho,
    ) -> Arc<Self> {
        Arc::new(Self {
            store_chirho: Arc::new(store_chirho),
            view_chirho,
            report_chirho,
            balance_read_chirho: None,
        })
    }

    pub fn new_with_balance_read_chirho(
        store_chirho: FsContentStoreChirho,
        view_chirho: ReplicaRefsViewChirho,
        report_chirho: RefSnapshotMountReportChirho,
        runner_chirho: ReplicaBalanceReadDagRunnerChirho,
        dag_chirho: ReplicaBalanceReadDagChirho,
    ) -> Arc<Self> {
        Arc::new(Self {
            store_chirho: Arc::new(store_chirho),
            view_chirho,
            report_chirho,
            balance_read_chirho: Some(Arc::new(ReplicaBalanceServeBindingChirho {
                runner_chirho,
                dag_chirho,
            })),
        })
    }

    /// Attach the explicitly prepared balance composition to an otherwise verified serve state.
    /// The caller must retain the sole `Arc` while wiring; shared live state is never rewritten.
    pub fn attach_balance_read_chirho(
        mut state_chirho: Arc<Self>,
        runner_chirho: ReplicaBalanceReadDagRunnerChirho,
        dag_chirho: ReplicaBalanceReadDagChirho,
    ) -> Arc<Self> {
        let state_mut_chirho = Arc::get_mut(&mut state_chirho)
            .expect("balance route must be wired before the serve state is shared");
        state_mut_chirho.balance_read_chirho = Some(Arc::new(ReplicaBalanceServeBindingChirho {
            runner_chirho,
            dag_chirho,
        }));
        state_chirho
    }
}

/// The GET-only route table. Any other method on these paths is a 405 from the router itself;
/// no route accepts a request body.
pub fn replica_serve_router_chirho(state_chirho: Arc<ReplicaServeStateChirho>) -> Router {
    Router::new()
        .route("/healthz-chirho", get(healthz_chirho))
        .route("/replica-status-chirho", get(status_chirho))
        .route("/view-balance-chirho", get(balance_chirho))
        .route("/replica-apps-chirho", get(apps_chirho))
        .route(
            "/runtime-package-chirho/:package_chirho/manifest-chirho",
            get(manifest_chirho),
        )
        .route(
            "/runtime-package-chirho/:package_chirho/executable-chirho",
            get(executable_chirho),
        )
        .with_state(state_chirho)
}

async fn balance_chirho(State(state_chirho): State<Arc<ReplicaServeStateChirho>>) -> Response {
    let Some(binding_chirho) = state_chirho.balance_read_chirho.as_ref() else {
        return not_public_chirho();
    };
    let result_chirho = binding_chirho.runner_chirho.run_page_chirho(
        state_chirho.store_chirho.as_ref(),
        &binding_chirho.dag_chirho,
        b"view-balance-request-chirho",
    );
    let result_chirho = match result_chirho {
        Ok(Ok(result_chirho)) => result_chirho,
        Ok(Err(_refusal_chirho)) => return not_public_chirho(),
        Err(_error_chirho) => return store_fault_chirho(),
    };
    let body_chirho = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Balance</title></head>\
<body data-verdict=\"degraded-replica-observed\" data-view-digest=\"{}\">\
<main><h1>Balance</h1><p>Degraded: replica-observed</p>\
<dl><dt>Lag</dt><dd>{} ms</dd><dt>Maximum observed lag</dt><dd>{} ms</dd></dl></main>\
</body></html>",
        result_chirho.output_hash_chirho.0,
        result_chirho.lag_ms_chirho,
        result_chirho.max_lag_ms_chirho,
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(axum::body::Body::from(body_chirho))
        .expect("balance response builds")
}

async fn healthz_chirho() -> &'static str {
    "ok"
}

fn plain_response_chirho(status_chirho: StatusCode, body_chirho: &str) -> Response {
    Response::builder()
        .status(status_chirho)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(axum::body::Body::from(body_chirho.to_string()))
        .expect("static response builds")
}

/// The uniform refusal: absent, malformed, non-public, and not-replicated all render identically
/// so the public surface leaks nothing about what exists beyond the public contract.
fn not_public_chirho() -> Response {
    plain_response_chirho(StatusCode::NOT_FOUND, "no such public artifact")
}

/// Backend faults render generically: store error strings can carry local paths, and a public
/// surface must never echo them (the same fixed-label posture as operator evidence).
fn store_fault_chirho() -> Response {
    plain_response_chirho(StatusCode::INTERNAL_SERVER_ERROR, "replica store fault")
}

/// Staleness surfaced (pre-commitment d): the mount report — seq, source time, labeled replica
/// clock, decision — as JSON.
async fn status_chirho(State(state_chirho): State<Arc<ReplicaServeStateChirho>>) -> Response {
    let balance_mount_chirho = match state_chirho.balance_read_chirho.as_ref() {
        Some(binding_chirho) => {
            let Some(pinned_chirho) = binding_chirho
                .runner_chirho
                .pinned_mount_coordinate_chirho()
            else {
                return store_fault_chirho();
            };
            let current_chirho = match binding_chirho
                .runner_chirho
                .current_mount_coordinate_chirho()
            {
                Ok(current_chirho) => current_chirho,
                Err(_) => return store_fault_chirho(),
            };
            Some(ReplicaBalanceMountStatusChirho {
                restart_required_chirho: pinned_chirho != &current_chirho,
                pinned_chirho: pinned_chirho.clone(),
                current_chirho,
            })
        }
        None => None,
    };
    let status_chirho = ReplicaServeStatusChirho {
        report_chirho: &state_chirho.report_chirho,
        balance_mount_chirho,
    };
    match serde_json::to_string(&status_chirho) {
        Ok(body_chirho) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body_chirho))
            .expect("status response builds"),
        Err(_) => store_fault_chirho(),
    }
}

#[derive(Serialize)]
struct ReplicaServeStatusChirho<'a> {
    #[serde(flatten)]
    report_chirho: &'a RefSnapshotMountReportChirho,
    #[serde(skip_serializing_if = "Option::is_none")]
    balance_mount_chirho: Option<ReplicaBalanceMountStatusChirho>,
}

#[derive(Serialize)]
struct ReplicaBalanceMountStatusChirho {
    pinned_chirho:
        cairn_replication_http_chirho::projection_replication_chirho::ReplicaProjectionMountCoordinateChirho,
    current_chirho:
        cairn_replication_http_chirho::projection_replication_chirho::ReplicaProjectionMountCoordinateChirho,
    restart_required_chirho: bool,
}

/// The discovery surface: the snapshot's ref names (bounded non-identifying labels) and their
/// target hashes — exactly what the source-signed snapshot published, nothing else.
async fn apps_chirho(State(state_chirho): State<Arc<ReplicaServeStateChirho>>) -> Response {
    let refs_chirho: BTreeMap<&str, &str> = state_chirho
        .view_chirho
        .ref_names_chirho()
        .filter_map(|name_chirho| {
            state_chirho
                .view_chirho
                .ref_hash_chirho(name_chirho)
                .map(|hash_chirho| (name_chirho, hash_chirho.0.as_str()))
        })
        .collect();
    match serde_json::to_string(&refs_chirho) {
        Ok(body_chirho) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body_chirho))
            .expect("apps response builds"),
        Err(_) => store_fault_chirho(),
    }
}

fn parse_addr_chirho(hex_chirho: &str) -> Option<HashChirho> {
    let well_formed_chirho = hex_chirho.len() == 64
        && hex_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase()
        });
    well_formed_chirho.then(|| HashChirho(hex_chirho.to_string()))
}

/// Load a stored manifest and pass it through the PURE public-artifact gate. `Ok(None)` means
/// "render the uniform refusal"; `Err` means a backend fault.
fn load_public_package_chirho(
    state_chirho: &ReplicaServeStateChirho,
    package_hex_chirho: &str,
) -> Result<Option<(RuntimePackageChirho, Vec<u8>)>, ()> {
    let Some(addr_chirho) = parse_addr_chirho(package_hex_chirho) else {
        return Ok(None);
    };
    let bytes_chirho = match state_chirho.store_chirho.get_chirho(&addr_chirho) {
        Ok(Some(bytes_chirho)) => bytes_chirho,
        Ok(None) => return Ok(None),
        Err(_) => return Err(()),
    };
    let Ok(package_chirho) = serde_json::from_slice::<RuntimePackageChirho>(&bytes_chirho) else {
        return Ok(None);
    };
    if ensure_public_runtime_package_artifact_chirho(&package_chirho).is_err() {
        return Ok(None);
    }
    Ok(Some((package_chirho, bytes_chirho)))
}

/// The stored canonical manifest bytes of a PUBLIC package, by hash.
async fn manifest_chirho(
    State(state_chirho): State<Arc<ReplicaServeStateChirho>>,
    AxumPathChirho(package_chirho): AxumPathChirho<String>,
) -> Response {
    match load_public_package_chirho(&state_chirho, &package_chirho) {
        Ok(Some((_package_chirho, bytes_chirho))) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(bytes_chirho))
            .expect("manifest response builds"),
        Ok(None) => not_public_chirho(),
        Err(()) => store_fault_chirho(),
    }
}

/// The executable bytes a PUBLIC manifest names — the only artifact the contract exposes. The
/// store's verify-on-read re-hashes the bytes before they leave, so a tampered replica object
/// faults instead of serving.
async fn executable_chirho(
    State(state_chirho): State<Arc<ReplicaServeStateChirho>>,
    AxumPathChirho(package_chirho): AxumPathChirho<String>,
) -> Response {
    let package_chirho = match load_public_package_chirho(&state_chirho, &package_chirho) {
        Ok(Some((package_chirho, _bytes_chirho))) => package_chirho,
        Ok(None) => return not_public_chirho(),
        Err(()) => return store_fault_chirho(),
    };
    match state_chirho
        .store_chirho
        .get_chirho(&package_chirho.executable_chirho)
    {
        Ok(Some(bytes_chirho)) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/wasm")
            .body(axum::body::Body::from(bytes_chirho))
            .expect("executable response builds"),
        Ok(None) => not_public_chirho(),
        Err(_) => store_fault_chirho(),
    }
}

/// Is this address one a replica may bind WITHOUT an explicit public-exposure approval? An
/// ALLOWLIST, deliberately: loopback and the private/link-local ranges (which cover the WireGuard
/// mesh, `10.100.0.0/24`) and nothing else. A blocklist of wildcards was the earlier shape and it
/// was bypassable — `[::ffff:0.0.0.0]` is not `is_unspecified()` yet binds every interface, and a
/// bare public IP is not a wildcard at all yet is exactly the exposure the rule exists to stop.
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is canonicalized to its IPv4 form BEFORE classification, so
/// the mapped spelling of an address is judged identically to the plain one.
fn is_private_bind_addr_chirho(ip_chirho: std::net::IpAddr) -> bool {
    let canonical_chirho = match ip_chirho {
        std::net::IpAddr::V6(v6_chirho) => match v6_chirho.to_ipv4_mapped() {
            Some(v4_chirho) => std::net::IpAddr::V4(v4_chirho),
            None => std::net::IpAddr::V6(v6_chirho),
        },
        plain_chirho => plain_chirho,
    };
    match canonical_chirho {
        std::net::IpAddr::V4(v4_chirho) => {
            // Never the wildcard (0.0.0.0 binds every interface, public ones included).
            !v4_chirho.is_unspecified()
                && (v4_chirho.is_loopback() || v4_chirho.is_private() || v4_chirho.is_link_local())
        }
        std::net::IpAddr::V6(v6_chirho) => {
            // `::` is the wildcard; `::1` is loopback; `fc00::/7` (unique-local) and `fe80::/10`
            // (link-local) are the private ranges. Everything else is public until approved.
            let segments_chirho = v6_chirho.segments();
            let unique_local_chirho = (segments_chirho[0] & 0xfe00) == 0xfc00;
            let link_local_chirho = (segments_chirho[0] & 0xffc0) == 0xfe80;
            !v6_chirho.is_unspecified()
                && (v6_chirho.is_loopback() || unique_local_chirho || link_local_chirho)
        }
    }
}

/// Pre-commitment (e) with teeth: bind the replica serve socket ONLY to loopback or a private/mesh
/// address, unless the caller EXPLICITLY opts into public exposure (a separate L.J. approval — the
/// cax11 Caddy-cutover precedent; mesh-only drills until then). The composition root passes the
/// WireGuard mesh IP. Wildcards (`0.0.0.0`, `::`, and the IPv4-mapped `::ffff:0.0.0.0`) and any
/// routable address are refused without the flag — the guard allowlists what is safe rather than
/// blocklisting the wildcard spellings it happens to know.
pub fn bind_replica_listener_chirho(
    addr_chirho: &str,
    allow_public_bind_chirho: bool,
) -> anyhow::Result<std::net::TcpListener> {
    let parsed_chirho: std::net::SocketAddr = addr_chirho
        .parse()
        .map_err(|_| anyhow::anyhow!("replica serve bind address is not host:port"))?;
    if !allow_public_bind_chirho && !is_private_bind_addr_chirho(parsed_chirho.ip()) {
        anyhow::bail!(
            "replica serve refuses this bind address by default: only loopback and private/mesh \
             addresses may be bound — public exposure of the artifact surface (a wildcard or a \
             routable address) is a separate explicit approval (bind the private mesh IP instead)"
        );
    }
    std::net::TcpListener::bind(parsed_chirho)
        .map_err(|error_chirho| anyhow::anyhow!("bind replica serve listener: {error_chirho}"))
}

/// Serve the router on an already-bound listener, blocking the calling thread (the composition
/// root owns process lifecycle, exactly like the replication source server helper).
pub fn serve_replica_blocking_chirho(
    listener_chirho: std::net::TcpListener,
    router_chirho: Router,
) -> anyhow::Result<()> {
    let runtime_chirho = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime_chirho.block_on(async move {
        listener_chirho.set_nonblocking(true)?;
        let tokio_listener_chirho = tokio::net::TcpListener::from_std(listener_chirho)?;
        axum::serve(tokio_listener_chirho, router_chirho)
            .await
            .map_err(anyhow::Error::from)
    })
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    // Fixtures SEED objects, so the test module imports the write trait. Production code in
    // this crate cannot reach it: the serve state holds only `Arc<dyn ContentReadChirho>`.
    use axum::body::to_bytes;
    use axum::http::Request;
    use cairn_core_chirho::cas_chirho::hash_chirho;
    use cairn_core_chirho::model_chirho::{DagChirho, HashChirho, NodeDefChirho, PortChirho};
    use cairn_core_chirho::ports_chirho::ContentStoreChirho;
    use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
    use cairn_ledger_model_chirho::record_chirho::HlcChirho;
    use cairn_ledger_model_chirho::LogIdChirho;
    use cairn_ledger_read_model_chirho::account_net_chirho::{
        canonical_account_net_projection_view_chirho, AccountNetProjectionRowChirho,
        AccountNetProjectionViewChirho, ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO,
    };
    use cairn_ledger_read_model_chirho::feeder_chirho::{
        view_bytes_digest_hex_chirho, FollowReceiptChirho, FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO,
    };
    use cairn_replication_chirho::ref_snapshot_chirho::{
        mount_ref_snapshot_chirho, FloorDecisionChirho, RefSnapshotChirho,
        RefSnapshotHeadRecordChirho, RefSnapshotMountReportChirho, REF_SNAPSHOT_HEAD_SCHEMA_CHIRHO,
    };
    use cairn_replication_http_chirho::projection_replication_chirho::{
        ProjectionReplicaMountChirho, ProjectionReplicaPullConfigChirho,
        ProjectionReplicationIdentityChirho, ReplicaMountedProjectionReadPortChirho,
        PROJECTION_REPLICA_MOUNT_SCHEMA_V1_CHIRHO,
    };
    use cairn_replication_http_chirho::{
        ReplicaBalanceReadDagChirho, ReplicaBalanceReadDagRunnerChirho,
    };
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tower::ServiceExt;

    /// Pre-commitment (e), classifier level: an ALLOWLIST. The earlier `is_unspecified()` blocklist
    /// passed `::ffff:0.0.0.0` (which binds every interface) and every routable public address;
    /// both are refused here. The socket-level regressions live in `tests/replica_serve_chirho.rs`.
    #[test]
    fn only_loopback_and_private_addresses_are_bindable_by_default_chirho() {
        for private_chirho in [
            "127.0.0.1",
            "::1",
            "10.100.0.1",
            "192.168.1.5",
            "172.16.0.9",
            "169.254.7.7",
            "fd00::1",
            "fe80::1",
            "::ffff:10.100.0.1",
        ] {
            assert!(
                is_private_bind_addr_chirho(private_chirho.parse().expect(private_chirho)),
                "{private_chirho} is private/loopback and must bind without approval"
            );
        }
        for public_chirho in [
            "0.0.0.0",
            "::",
            "::ffff:0.0.0.0",
            "8.8.8.8",
            "::ffff:8.8.8.8",
            "2001:4860:4860::8888",
        ] {
            assert!(
                !is_private_bind_addr_chirho(public_chirho.parse().expect(public_chirho)),
                "{public_chirho} is a wildcard or routable address and needs explicit approval"
            );
        }
        let message_chirho = bind_replica_listener_chirho("[::ffff:0.0.0.0]:0", false)
            .expect_err("the IPv4-mapped wildcard must be refused")
            .to_string();
        assert!(
            message_chirho.contains("refuses this bind address"),
            "{message_chirho}"
        );
        assert!(bind_replica_listener_chirho("127.0.0.1:0", false).is_ok());
        assert!(bind_replica_listener_chirho("0.0.0.0:0", true).is_ok());
        assert!(bind_replica_listener_chirho("not-an-addr", false).is_err());
    }

    #[tokio::test]
    async fn wired_balance_route_serves_degraded_and_unwired_route_refuses_chirho() {
        let root_chirho = temp_root_for_test_chirho("wired-balance");
        let store_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
        let target_hash_chirho = store_chirho.put_chirho(b"target").unwrap();
        let mut refs_chirho = BTreeMap::new();
        refs_chirho.insert("app/demo-chirho".to_owned(), target_hash_chirho);
        let snapshot_chirho = RefSnapshotChirho::new_chirho(refs_chirho, 1, 1_000).unwrap();
        let snapshot_bytes_chirho = snapshot_chirho.canonical_bytes_chirho().unwrap();
        let snapshot_hash_chirho = store_chirho.put_chirho(&snapshot_bytes_chirho).unwrap();
        let head_chirho = RefSnapshotHeadRecordChirho {
            schema_chirho: REF_SNAPSHOT_HEAD_SCHEMA_CHIRHO.to_owned(),
            seq_chirho: 1,
            source_time_unix_chirho: 1_000,
            snapshot_hash_chirho: snapshot_hash_chirho.clone(),
            refs_digest_chirho: snapshot_chirho.refs_digest_chirho().unwrap(),
            ref_count_chirho: 1,
            key_id_chirho: "source-key-chirho".to_owned(),
            sig_chirho: "unused-in-local-mount-test-chirho".to_owned(),
        };
        let view_chirho = mount_ref_snapshot_chirho(&store_chirho, &head_chirho).unwrap();
        let report_chirho = RefSnapshotMountReportChirho {
            schema_chirho: "ref-snapshot-mount-report-v1-chirho".to_owned(),
            seq_chirho: 1,
            source_time_unix_chirho: 1_000,
            verified_at_unix_chirho: 1_100,
            source_key_id_chirho: "source-key-chirho".to_owned(),
            ref_count_chirho: 1,
            decision_chirho: FloorDecisionChirho::FreshMountChirho,
        };

        // Fixed valid verification fixture: replica-side source holds no key or signing capability.
        let identity_chirho = ProjectionReplicationIdentityChirho {
            projection_name_chirho: "credits-balance-chirho".to_owned(),
            descriptor_digest_chirho: "1".repeat(64),
            source_cluster_chirho: "test-cluster-chirho".to_owned(),
            source_genesis_digest_chirho: "2".repeat(64),
            feeder_pubkey_hex_chirho:
                "3eba45c9fffeabf841777b7281427b2ef01812a5cbe0153edd89bdb214271f92".to_owned(),
        };
        let view_model_chirho = AccountNetProjectionViewChirho {
            schema_chirho: ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO.to_owned(),
            rows_chirho: vec![AccountNetProjectionRowChirho {
                account_chirho: LogIdChirho::new_chirho(
                    "distinctive-owner-chirho",
                    AssetKindIdChirho("credits-chirho".to_owned()),
                ),
                account_net_chirho: 7400000000000000000,
            }],
        };
        let view_bytes_chirho =
            canonical_account_net_projection_view_chirho(&view_model_chirho).unwrap();
        let receipt_chirho = FollowReceiptChirho {
            schema_chirho: FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO.to_owned(),
            projection_name_chirho: identity_chirho.projection_name_chirho.clone(),
            descriptor_digest_chirho: DigestChirho(
                identity_chirho.descriptor_digest_chirho.clone(),
            ),
            source_cluster_chirho: identity_chirho.source_cluster_chirho.clone(),
            source_genesis_digest_chirho: DigestChirho(
                identity_chirho.source_genesis_digest_chirho.clone(),
            ),
            source_tail_seq_chirho: 7,
            source_tail_hlc_chirho: HlcChirho {
                physical_ms_chirho: 1_000,
                logical_chirho: 0,
            },
            source_tail_line_digest_chirho: DigestChirho("a".repeat(64)),
            view_digest_hex_chirho: view_bytes_digest_hex_chirho(&view_bytes_chirho),
            feeder_sig_chirho:
                "4d9b408aca2e426c6cbb811c1afafe753e7909c04b262e1134a83af4af03fa904f86030b60b50b3e28b22772058d779b9af2e754d03d2b4405f91b95f3c53f04"
                    .to_owned(),
        };
        let projection_dir_chirho = root_chirho.join("projection-replica-chirho");
        std::fs::create_dir_all(projection_dir_chirho.join("views-chirho")).unwrap();
        std::fs::write(
            projection_dir_chirho
                .join("views-chirho")
                .join(&receipt_chirho.view_digest_hex_chirho),
            &view_bytes_chirho,
        )
        .unwrap();
        let mount_chirho = ProjectionReplicaMountChirho {
            schema_chirho: PROJECTION_REPLICA_MOUNT_SCHEMA_V1_CHIRHO.to_owned(),
            identity_chirho: identity_chirho.clone(),
            mounted_at_unix_chirho: 1_100,
            receipt_chirho,
        };
        let state_digest_hex_chirho = mount_chirho.receipt_chirho.view_digest_hex_chirho.clone();
        std::fs::write(
            projection_dir_chirho.join("mounted-projection-chirho.json"),
            serde_json::to_vec(&mount_chirho).unwrap(),
        )
        .unwrap();
        let projection_config_chirho = ProjectionReplicaPullConfigChirho {
            source_url_chirho: "http://127.0.0.1:0".to_owned(),
            bearer_env_chirho: "unused-chirho".to_owned(),
            replica_root_chirho: root_chirho.clone(),
            identity_chirho,
            inspect_accounts_chirho: Vec::new(),
        };
        let wasm_chirho = wat::parse_bytes(include_bytes!(
            "../../../../examples-chirho/upcase-chirho.wat"
        ))
        .unwrap();
        let wasm_object_hash_chirho = store_chirho.put_chirho(&wasm_chirho).unwrap();
        let schema_hash_chirho = HashChirho("3".repeat(64));
        let node_chirho = NodeDefChirho {
            name_chirho: "upcase-chirho".to_owned(),
            impl_wasm_chirho: wasm_object_hash_chirho,
            entry_chirho: "upcase_chirho".to_owned(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in".to_owned(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out".to_owned(),
                schema_chirho: schema_hash_chirho,
            }],
            fuel_limit_chirho: 5_000_000,
            ..Default::default()
        };
        let node_hash_chirho = store_chirho
            .put_chirho(&serde_json::to_vec(&node_chirho).unwrap())
            .unwrap();
        let transformed_bytes_chirho = view_bytes_chirho.to_ascii_uppercase();
        let expected_output_hash_chirho = hash_chirho(&transformed_bytes_chirho);
        let dag_chirho = ReplicaBalanceReadDagChirho {
            before_query_dag_chirho: None,
            after_query_dag_chirho: Some(DagChirho {
                nodes_chirho: vec![node_hash_chirho],
                edges_chirho: Vec::new(),
            }),
            expected_output_hash_chirho: expected_output_hash_chirho.clone(),
        };
        assert_ne!(expected_output_hash_chirho.0, state_digest_hex_chirho);
        let runner_chirho = ReplicaBalanceReadDagRunnerChirho::new_chirho(
            ReplicaMountedProjectionReadPortChirho::new_chirho(
                projection_config_chirho,
                1_100,
                100,
            ),
        );
        let wired_state_chirho = ReplicaServeStateChirho::new_with_balance_read_chirho(
            store_chirho,
            view_chirho.clone(),
            report_chirho.clone(),
            runner_chirho,
            dag_chirho,
        );
        let wired_response_chirho = replica_serve_router_chirho(wired_state_chirho)
            .oneshot(
                Request::builder()
                    .uri("/view-balance-chirho")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wired_response_chirho.status(), StatusCode::OK);
        assert_eq!(
            wired_response_chirho.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        let wired_body_chirho = to_bytes(wired_response_chirho.into_body(), 64 * 1024)
            .await
            .unwrap();
        let wired_body_text_chirho = String::from_utf8(wired_body_chirho.to_vec()).unwrap();
        assert!(wired_body_text_chirho.contains("Degraded: replica-observed"));
        assert!(wired_body_text_chirho.contains(&expected_output_hash_chirho.0));
        assert!(!wired_body_text_chirho.contains(&state_digest_hex_chirho));
        assert!(wired_body_text_chirho.contains("100 ms"));
        assert!(wired_body_text_chirho.contains("Maximum observed lag"));
        for pii_needle_chirho in [
            "distinctive-owner-chirho",
            "owner_chirho",
            "email",
            "subject",
            "7400000000000000000",
        ] {
            assert!(!wired_body_text_chirho.contains(pii_needle_chirho));
        }
        let unwired_state_chirho = ReplicaServeStateChirho::new_chirho(
            FsContentStoreChirho::new_chirho(&root_chirho),
            view_chirho,
            report_chirho,
        );
        let unwired_response_chirho = replica_serve_router_chirho(unwired_state_chirho)
            .oneshot(
                Request::builder()
                    .uri("/view-balance-chirho")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unwired_response_chirho.status(), StatusCode::NOT_FOUND);
    }

    fn temp_root_for_test_chirho(label_chirho: &str) -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-replica-serve-{label_chirho}-{}-{}",
            std::process::id(),
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root_chirho);
        std::fs::create_dir_all(&root_chirho).unwrap();
        root_chirho
    }
}
