// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! B2.1 replica serve end-to-end over the REAL pull pipeline: source export → localfs transport
//! (proving the snapshot log crosses) → verified receive → floor-checked mount → GET-only serving
//! of the M150 public contract, with the refusal matrix (server-profile, capability-bearing,
//! extra-object, absent, malformed) rendering one uniform non-leaking 404 and mutations 405ing.

use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::{CapabilityChirho, HashChirho, RefsChirho};
use cairn_core_chirho::ports_chirho::ContentStoreChirho;
use cairn_core_chirho::refs_chirho::save_refs_chirho;
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::HlcChirho;
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_ledger_read_model_chirho::account_net_chirho::{
    canonical_account_net_projection_view_chirho, AccountNetProjectionRowChirho,
    AccountNetProjectionViewChirho, ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_read_model_chirho::feeder_chirho::{
    follow_receipt_signed_content_chirho, view_bytes_digest_hex_chirho, FollowReceiptChirho,
    FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO,
};
use cairn_model_runtime_chirho::{
    RuntimePackageChirho, RuntimePackageItemKindChirho, RuntimeProfileKindChirho, BYTES_ABI_CHIRHO,
};
use cairn_replica_serve_http_chirho::composition_chirho::{
    load_verified_replica_serve_chirho, ReplicaBalanceReadModeChirho,
    ReplicaBalanceServeConfigChirho, ReplicaServeConfigChirho,
};
use cairn_replica_serve_http_chirho::{
    bind_replica_listener_chirho, replica_serve_router_chirho, serve_replica_blocking_chirho,
    ReplicaServeStateChirho,
};
use cairn_replication_chirho::membership_chirho::{
    unsigned_membership_roster_message_chirho, MembershipActionChirho,
    MembershipRosterRecordChirho, MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO,
};
use cairn_replication_chirho::receive_objects_chirho;
use cairn_replication_chirho::ref_snapshot_chirho::{
    export_ref_snapshot_chirho, FloorDecisionChirho, REF_SNAPSHOT_LOG_FILE_CHIRHO,
};
use cairn_replication_chirho::ReplicationSourceChirho;
use cairn_replication_http_chirho::projection_replication_chirho::{
    mounted_projection_path_chirho, ProjectionReplicaMountChirho,
    ProjectionReplicaPullConfigChirho, ProjectionReplicationIdentityChirho,
    PROJECTION_REPLICA_MOUNT_SCHEMA_V1_CHIRHO,
};
use cairn_replication_localfs_chirho::{FsReplicaQuarantineChirho, LocalFsReplicationSourceChirho};
use cairn_signer_chirho::signer_chirho;
use cairn_store_fs_chirho::FsContentStoreChirho;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-repserve-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

/// Store a manifest with the given shape; return it and its content address.
fn put_package_chirho(
    store_chirho: &FsContentStoreChirho,
    profile_chirho: RuntimeProfileKindChirho,
    capabilities_chirho: Vec<CapabilityChirho>,
    wasm_chirho: &[u8],
    extra_object_chirho: bool,
) -> (RuntimePackageChirho, HashChirho) {
    let executable_chirho = store_chirho.put_chirho(wasm_chirho).unwrap();
    let mut object_hashes_chirho = vec![executable_chirho.clone()];
    if extra_object_chirho {
        object_hashes_chirho.push(store_chirho.put_chirho(b"an extra exposed object").unwrap());
    }
    let package_chirho = RuntimePackageChirho {
        profile_chirho,
        module_chirho: hash_chirho(b"module descriptor"),
        dag_chirho: hash_chirho(b"dag descriptor"),
        executable_chirho,
        entry_chirho: "run_chirho".to_string(),
        abi_chirho: BYTES_ABI_CHIRHO.to_string(),
        inputs_chirho: Vec::new(),
        outputs_chirho: Vec::new(),
        capabilities_chirho,
        included_items_chirho: vec![RuntimePackageItemKindChirho::ExecutableWasmChirho],
        excluded_items_chirho: Vec::new(),
        object_hashes_chirho,
    };
    let bytes_chirho = serde_json::to_vec(&package_chirho).unwrap();
    let manifest_hash_chirho = store_chirho.put_chirho(&bytes_chirho).unwrap();
    (package_chirho, manifest_hash_chirho)
}

fn start_server_chirho(state_chirho: Arc<ReplicaServeStateChirho>) -> String {
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url_chirho = format!("http://{}", listener_chirho.local_addr().unwrap());
    let router_chirho = replica_serve_router_chirho(state_chirho);
    std::thread::spawn(move || {
        let _ = serve_replica_blocking_chirho(listener_chirho, router_chirho);
    });
    base_url_chirho
}

fn write_single_source_roster_chirho(
    operator_root_chirho: &std::path::Path,
    roster_path_chirho: &std::path::Path,
    source_pubkey_hex_chirho: &str,
) -> String {
    let operator_pubkey_hex_chirho =
        signer_chirho::pubkey_hex_chirho(operator_root_chirho).unwrap();
    let mut record_chirho = MembershipRosterRecordChirho {
        schema_chirho: MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho: 0,
        action_chirho: MembershipActionChirho::AddNodeChirho,
        node_pubkey_hex_chirho: source_pubkey_hex_chirho.to_string(),
        region_label_chirho: "source-region-chirho".to_string(),
        at_ms_chirho: 1_000,
        operator_key_id_chirho: operator_pubkey_hex_chirho.clone(),
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_membership_roster_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(operator_root_chirho, &message_chirho).unwrap();
    let mut roster_line_chirho = serde_json::to_vec(&record_chirho).unwrap();
    roster_line_chirho.push(b'\n');
    std::fs::write(roster_path_chirho, roster_line_chirho).unwrap();
    operator_pubkey_hex_chirho
}

#[allow(
    clippy::too_many_arguments,
    reason = "the fixture binds one complete signed projection-mount coordinate"
)]
fn write_signed_projection_mount_chirho(
    replica_root_chirho: &std::path::Path,
    feeder_root_chirho: &std::path::Path,
    identity_chirho: &ProjectionReplicationIdentityChirho,
    account_chirho: &LogIdChirho,
    source_tail_seq_chirho: u64,
    source_tail_physical_ms_chirho: u64,
    source_tail_digit_chirho: char,
    account_net_chirho: u64,
    mounted_at_unix_chirho: u64,
) -> (ProjectionReplicaMountChirho, PathBuf) {
    let view_chirho = AccountNetProjectionViewChirho {
        schema_chirho: ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO.to_owned(),
        rows_chirho: vec![AccountNetProjectionRowChirho {
            account_chirho: account_chirho.clone(),
            account_net_chirho,
        }],
    };
    let view_bytes_chirho = canonical_account_net_projection_view_chirho(&view_chirho).unwrap();
    let mut receipt_chirho = FollowReceiptChirho {
        schema_chirho: FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO.to_owned(),
        projection_name_chirho: identity_chirho.projection_name_chirho.clone(),
        descriptor_digest_chirho: DigestChirho(identity_chirho.descriptor_digest_chirho.clone()),
        source_cluster_chirho: identity_chirho.source_cluster_chirho.clone(),
        source_genesis_digest_chirho: DigestChirho(
            identity_chirho.source_genesis_digest_chirho.clone(),
        ),
        source_tail_seq_chirho,
        source_tail_hlc_chirho: HlcChirho {
            physical_ms_chirho: source_tail_physical_ms_chirho,
            logical_chirho: 0,
        },
        source_tail_line_digest_chirho: DigestChirho(
            source_tail_digit_chirho.to_string().repeat(64),
        ),
        view_digest_hex_chirho: view_bytes_digest_hex_chirho(&view_bytes_chirho),
        feeder_sig_chirho: String::new(),
    };
    let signed_content_chirho = follow_receipt_signed_content_chirho(&receipt_chirho).unwrap();
    receipt_chirho.feeder_sig_chirho =
        signer_chirho::sign_message_chirho(feeder_root_chirho, signed_content_chirho.as_bytes())
            .unwrap();
    let mount_path_chirho = mounted_projection_path_chirho(replica_root_chirho);
    let view_dir_chirho = mount_path_chirho.parent().unwrap().join("views-chirho");
    std::fs::create_dir_all(&view_dir_chirho).unwrap();
    let view_path_chirho = view_dir_chirho.join(&receipt_chirho.view_digest_hex_chirho);
    std::fs::write(&view_path_chirho, view_bytes_chirho).unwrap();
    let mount_chirho = ProjectionReplicaMountChirho {
        schema_chirho: PROJECTION_REPLICA_MOUNT_SCHEMA_V1_CHIRHO.to_owned(),
        identity_chirho: identity_chirho.clone(),
        mounted_at_unix_chirho,
        receipt_chirho,
    };
    std::fs::write(
        mount_path_chirho,
        serde_json::to_vec(&mount_chirho).unwrap(),
    )
    .unwrap();
    (mount_chirho, view_path_chirho)
}

fn projection_mount_coordinate_json_chirho(
    mount_chirho: &ProjectionReplicaMountChirho,
) -> serde_json::Value {
    serde_json::json!({
        "source_tail_seq_chirho": mount_chirho.receipt_chirho.source_tail_seq_chirho,
        "source_tail_hlc_chirho": mount_chirho.receipt_chirho.source_tail_hlc_chirho,
        "source_tail_line_digest_chirho": mount_chirho
            .receipt_chirho
            .source_tail_line_digest_chirho
            .0,
        "view_digest_hex_chirho": mount_chirho.receipt_chirho.view_digest_hex_chirho,
    })
}

fn get_chirho(url_chirho: &str) -> (u16, Vec<u8>, String) {
    match ureq::AgentBuilder::new()
        .redirects(0)
        .build()
        .get(url_chirho)
        .call()
    {
        Ok(response_chirho) => {
            let status_chirho = response_chirho.status();
            let content_type_chirho = response_chirho.content_type().to_string();
            let mut body_chirho = Vec::new();
            response_chirho
                .into_reader()
                .read_to_end(&mut body_chirho)
                .unwrap();
            (status_chirho, body_chirho, content_type_chirho)
        }
        // ureq surfaces every non-2xx as an Err — the BODY must still be read here, or the
        // non-leak assertions below would compare empty vectors and pass vacuously.
        Err(ureq::Error::Status(code_chirho, response_chirho)) => {
            let content_type_chirho = response_chirho.content_type().to_string();
            let mut body_chirho = Vec::new();
            response_chirho
                .into_reader()
                .read_to_end(&mut body_chirho)
                .unwrap();
            (code_chirho, body_chirho, content_type_chirho)
        }
        Err(error_chirho) => panic!("probe transport failed: {error_chirho}"),
    }
}

/// Where the fs store keeps one object — used ONLY by the forced-fault test, which corrupts a
/// replica object on disk to drive the store's verify-on-read (M142) failure leg.
fn object_path_for_addr_chirho(
    replica_root_chirho: &std::path::Path,
    addr_chirho: &HashChirho,
) -> PathBuf {
    replica_root_chirho
        .join("objects-chirho")
        .join(&addr_chirho.0[..2])
        .join(&addr_chirho.0[2..])
}

/// The one full pipeline every probe below shares: seed, export, REAL localfs pull, mount, serve.
struct ServedReplicaChirho {
    base_url_chirho: String,
    public_manifest_chirho: HashChirho,
    public_package_chirho: RuntimePackageChirho,
    wasm_chirho: Vec<u8>,
    refused_manifests_chirho: Vec<HashChirho>,
    ghost_manifest_chirho: HashChirho,
    /// Public-shaped manifests whose HASH FIELDS are malformed (empty, short, multi-byte,
    /// traversal-shaped) — manifest-sourced strings that must never reach a store read.
    malformed_hash_manifests_chirho: Vec<HashChirho>,
    replica_root_chirho: PathBuf,
    config_chirho: ReplicaServeConfigChirho,
    projection_feeder_root_chirho: PathBuf,
    projection_identity_chirho: ProjectionReplicationIdentityChirho,
    projection_account_chirho: LogIdChirho,
    initial_projection_mount_chirho: ProjectionReplicaMountChirho,
    initial_projection_digest_chirho: String,
}

fn served_replica_chirho() -> ServedReplicaChirho {
    let source_root_chirho = tmp_root_chirho("src");
    let source_store_chirho = FsContentStoreChirho::new_chirho(&source_root_chirho);
    let wasm_chirho = b"\0asm fake executable chirho".to_vec();
    let (public_package_chirho, public_manifest_chirho) = put_package_chirho(
        &source_store_chirho,
        RuntimeProfileKindChirho::BrowserChirho,
        Vec::new(),
        &wasm_chirho,
        false,
    );
    let (_server_pkg_chirho, server_manifest_chirho) = put_package_chirho(
        &source_store_chirho,
        RuntimeProfileKindChirho::ServerChirho,
        Vec::new(),
        b"server-profile wasm",
        false,
    );
    let (_cap_pkg_chirho, capability_manifest_chirho) = put_package_chirho(
        &source_store_chirho,
        RuntimeProfileKindChirho::BrowserChirho,
        vec![CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "demo/".to_string(),
        }],
        b"capability wasm",
        false,
    );
    let (_extra_pkg_chirho, extra_manifest_chirho) = put_package_chirho(
        &source_store_chirho,
        RuntimeProfileKindChirho::BrowserChirho,
        Vec::new(),
        b"extra-object wasm",
        true,
    );
    // A public-shaped manifest whose executable bytes were never stored: the "not replicated"
    // honest case — the manifest gate passes, the executable renders the uniform refusal.
    let ghost_package_chirho = RuntimePackageChirho {
        executable_chirho: hash_chirho(b"never stored bytes"),
        object_hashes_chirho: vec![hash_chirho(b"never stored bytes")],
        ..put_package_chirho(
            &source_store_chirho,
            RuntimeProfileKindChirho::BrowserChirho,
            Vec::new(),
            b"ghost placeholder",
            false,
        )
        .0
    };
    let ghost_manifest_chirho = source_store_chirho
        .put_chirho(&serde_json::to_vec(&ghost_package_chirho).unwrap())
        .unwrap();

    // B2.5(b): public-shaped manifests whose EXECUTABLE hash field is not a content address at
    // all. A manifest is data on a replica — a malicious or buggy source can write anything here.
    // The empty and multi-byte values panic a naive sharded-path split (`hex[..2]`); the
    // traversal-shaped one would address a file outside the object tree (verify-on-read would
    // still refuse the CONTENT, but the read must not be reachable at all).
    let mut malformed_hash_manifests_chirho: Vec<HashChirho> = Vec::new();
    for bad_hash_chirho in [
        "",
        "a",
        "aé",
        "aa../../signing-key-chirho.bin",
        &"A".repeat(64),
    ] {
        let bad_package_chirho = RuntimePackageChirho {
            executable_chirho: HashChirho(bad_hash_chirho.to_string()),
            object_hashes_chirho: vec![HashChirho(bad_hash_chirho.to_string())],
            ..put_package_chirho(
                &source_store_chirho,
                RuntimeProfileKindChirho::BrowserChirho,
                Vec::new(),
                b"malformed-hash placeholder",
                false,
            )
            .0
        };
        malformed_hash_manifests_chirho.push(
            source_store_chirho
                .put_chirho(&serde_json::to_vec(&bad_package_chirho).unwrap())
                .unwrap(),
        );
    }

    let mut branches_chirho: BTreeMap<String, HashChirho> = BTreeMap::new();
    branches_chirho.insert("app/demo".to_string(), public_manifest_chirho.clone());
    branches_chirho.insert(
        "app-route/demo/root".to_string(),
        public_manifest_chirho.clone(),
    );
    save_refs_chirho(
        &source_root_chirho,
        &RefsChirho {
            branches_chirho,
            tags_chirho: BTreeMap::new(),
            head_chirho: "app/demo".to_string(),
        },
    )
    .unwrap();
    export_ref_snapshot_chirho(&source_root_chirho, 1_000).unwrap();

    // The REAL pull: localfs transport for objects AND the snapshot log (allowlist regression).
    let replica_root_chirho = tmp_root_chirho("replica");
    let replica_store_chirho = FsContentStoreChirho::new_chirho(&replica_root_chirho);
    let source_chirho = LocalFsReplicationSourceChirho::new_chirho(&source_root_chirho);
    let quarantine_chirho = FsReplicaQuarantineChirho::new_chirho(&replica_root_chirho);
    let (pull_chirho, _receipts_chirho) =
        receive_objects_chirho(&source_chirho, &replica_store_chirho, &quarantine_chirho).unwrap();
    assert_eq!(pull_chirho.quarantined_chirho, 0);
    let log_chirho = source_chirho
        .fetch_named_log_chirho(REF_SNAPSHOT_LOG_FILE_CHIRHO)
        .unwrap()
        .expect("the localfs transport must carry the allowlisted snapshot log");
    std::fs::write(
        replica_root_chirho.join(REF_SNAPSHOT_LOG_FILE_CHIRHO),
        &log_chirho,
    )
    .unwrap();
    let source_pubkey_hex_chirho = signer_chirho::pubkey_hex_chirho(&source_root_chirho).unwrap();
    let operator_root_chirho = tmp_root_chirho("operator");
    let roster_path_chirho = replica_root_chirho.join("membership-roster-chirho.jsonl");
    let operator_pubkey_hex_chirho = write_single_source_roster_chirho(
        &operator_root_chirho,
        &roster_path_chirho,
        &source_pubkey_hex_chirho,
    );
    let projection_feeder_root_chirho = tmp_root_chirho("projection-feeder");
    let projection_identity_chirho = ProjectionReplicationIdentityChirho {
        projection_name_chirho: "credits-balance-chirho".to_owned(),
        descriptor_digest_chirho: "1".repeat(64),
        source_cluster_chirho: "credits-demo-cluster-chirho".to_owned(),
        source_genesis_digest_chirho: "2".repeat(64),
        feeder_pubkey_hex_chirho: signer_chirho::pubkey_hex_chirho(&projection_feeder_root_chirho)
            .unwrap(),
    };
    let projection_account_chirho = LogIdChirho::new_chirho(
        "synthetic-payer-chirho",
        AssetKindIdChirho("credits-chirho".to_owned()),
    );
    let (initial_projection_mount_chirho, _initial_view_path_chirho) =
        write_signed_projection_mount_chirho(
            &replica_root_chirho,
            &projection_feeder_root_chirho,
            &projection_identity_chirho,
            &projection_account_chirho,
            7,
            7_776_000,
            'a',
            90,
            7_776,
        );
    let projection_config_chirho = ProjectionReplicaPullConfigChirho {
        source_url_chirho: "http://127.0.0.1:1".to_owned(),
        bearer_env_chirho: "unused-projection-bearer-chirho".to_owned(),
        replica_root_chirho: replica_root_chirho.clone(),
        identity_chirho: projection_identity_chirho.clone(),
        inspect_accounts_chirho: vec![projection_account_chirho.clone()],
    };
    let config_chirho = ReplicaServeConfigChirho {
        replica_root_chirho: replica_root_chirho.clone(),
        listen_addr_chirho: "127.0.0.1:0".to_string(),
        roster_lines_path_chirho: roster_path_chirho,
        operator_pubkey_hex_chirho,
        source_pubkey_hex_chirho,
        allow_public_bind_chirho: false,
        balance_read_chirho: Some(ReplicaBalanceServeConfigChirho {
            projection_chirho: projection_config_chirho,
            mode_chirho: ReplicaBalanceReadModeChirho::DirectVerifiedMountChirho,
            max_lag_ms_chirho: 2_000,
        }),
    };
    let first_prepared_chirho = load_verified_replica_serve_chirho(&config_chirho, 7_776).unwrap();
    assert_eq!(
        first_prepared_chirho.mount_report_chirho.decision_chirho,
        FloorDecisionChirho::FreshMountChirho
    );
    let prepared_chirho = load_verified_replica_serve_chirho(&config_chirho, 7_777).unwrap();
    assert_eq!(
        prepared_chirho.mount_report_chirho.decision_chirho,
        FloorDecisionChirho::IdempotentRemountChirho,
        "a restarted replica must remount the floor-identical signed snapshot"
    );
    assert_eq!(prepared_chirho.source_region_chirho, "source-region-chirho");
    let base_url_chirho = start_server_chirho(prepared_chirho.state_chirho);
    std::fs::remove_dir_all(source_root_chirho).unwrap();
    std::fs::remove_dir_all(operator_root_chirho).unwrap();
    ServedReplicaChirho {
        base_url_chirho,
        public_manifest_chirho,
        public_package_chirho,
        wasm_chirho,
        refused_manifests_chirho: vec![
            server_manifest_chirho,
            capability_manifest_chirho,
            extra_manifest_chirho,
        ],
        ghost_manifest_chirho,
        malformed_hash_manifests_chirho,
        replica_root_chirho,
        config_chirho,
        projection_feeder_root_chirho,
        projection_identity_chirho,
        projection_account_chirho,
        initial_projection_digest_chirho: initial_projection_mount_chirho
            .receipt_chirho
            .view_digest_hex_chirho
            .clone(),
        initial_projection_mount_chirho,
    }
}

#[test]
fn production_balance_config_refuses_an_arbitrary_dag_chirho() {
    let fixed_config_chirho = serde_json::json!({
        "replica_root_chirho": "/tmp/replica-chirho",
        "listen_addr_chirho": "127.0.0.1:0",
        "roster_lines_path_chirho": "/tmp/roster-chirho.jsonl",
        "operator_pubkey_hex_chirho": "1".repeat(64),
        "source_pubkey_hex_chirho": "2".repeat(64),
        "balance_read_chirho": {
            "projection_chirho": {
                "source_url_chirho": "http://127.0.0.1:1",
                "bearer_env_chirho": "UNUSED_PROJECTION_BEARER_CHIRHO",
                "replica_root_chirho": "/tmp/replica-chirho",
                "identity_chirho": {
                    "projection_name_chirho": "credits-balance-chirho",
                    "descriptor_digest_chirho": "3".repeat(64),
                    "source_cluster_chirho": "credits-demo-cluster-chirho",
                    "source_genesis_digest_chirho": "4".repeat(64),
                    "feeder_pubkey_hex_chirho": "5".repeat(64)
                },
                "inspect_accounts_chirho": []
            },
            "mode_chirho": "direct-verified-mount-chirho",
            "max_lag_ms_chirho": 2000
        }
    });
    serde_json::from_value::<ReplicaServeConfigChirho>(fixed_config_chirho.clone())
        .expect("the fixed verified-mount production mode must parse");

    let mut arbitrary_config_chirho = fixed_config_chirho;
    arbitrary_config_chirho["balance_read_chirho"]["dag_chirho"] = serde_json::json!({
        "before_query_dag_chirho": null,
        "after_query_dag_chirho": null,
        "expected_output_hash_chirho": "6".repeat(64)
    });
    let refusal_chirho =
        serde_json::from_value::<ReplicaServeConfigChirho>(arbitrary_config_chirho)
            .expect_err("production config must not accept caller-selected DAG hashes");
    let refusal_message_chirho = refusal_chirho.to_string();
    assert!(refusal_message_chirho.contains("unknown field `dag_chirho`"));
    assert!(!refusal_message_chirho.contains("missing field `mode_chirho`"));
}

#[test]
fn valid_projection_advance_requires_restart_and_tamper_refuses_before_the_dag_gate_chirho() {
    let served_chirho = served_replica_chirho();
    let initial_balance_chirho = get_chirho(&format!(
        "{}/view-balance-chirho",
        served_chirho.base_url_chirho
    ));
    assert_eq!(initial_balance_chirho.0, 200);
    assert!(String::from_utf8(initial_balance_chirho.1)
        .unwrap()
        .contains(&served_chirho.initial_projection_digest_chirho));
    let initial_status_chirho = get_chirho(&format!(
        "{}/replica-status-chirho",
        served_chirho.base_url_chirho
    ));
    assert_eq!(initial_status_chirho.0, 200);
    let initial_status_json_chirho: serde_json::Value =
        serde_json::from_slice(&initial_status_chirho.1).unwrap();
    assert_eq!(
        initial_status_json_chirho["balance_mount_chirho"]["restart_required_chirho"],
        false
    );
    let initial_coordinate_chirho =
        projection_mount_coordinate_json_chirho(&served_chirho.initial_projection_mount_chirho);
    assert_eq!(
        initial_status_json_chirho["balance_mount_chirho"]["pinned_chirho"],
        initial_coordinate_chirho
    );
    assert_eq!(
        initial_status_json_chirho["balance_mount_chirho"]["current_chirho"],
        initial_coordinate_chirho
    );

    let (advanced_mount_chirho, advanced_view_path_chirho) = write_signed_projection_mount_chirho(
        &served_chirho.replica_root_chirho,
        &served_chirho.projection_feeder_root_chirho,
        &served_chirho.projection_identity_chirho,
        &served_chirho.projection_account_chirho,
        8,
        7_777_000,
        'b',
        80,
        7_777,
    );
    assert_ne!(
        advanced_mount_chirho.receipt_chirho.view_digest_hex_chirho,
        served_chirho.initial_projection_digest_chirho
    );
    let stale_process_balance_chirho = get_chirho(&format!(
        "{}/view-balance-chirho",
        served_chirho.base_url_chirho
    ));
    assert_eq!(stale_process_balance_chirho.0, 500);

    let advanced_status_chirho = get_chirho(&format!(
        "{}/replica-status-chirho",
        served_chirho.base_url_chirho
    ));
    assert_eq!(advanced_status_chirho.0, 200);
    let advanced_status_json_chirho: serde_json::Value =
        serde_json::from_slice(&advanced_status_chirho.1).unwrap();
    assert_eq!(
        advanced_status_json_chirho["balance_mount_chirho"]["restart_required_chirho"],
        true
    );
    let advanced_coordinate_chirho =
        projection_mount_coordinate_json_chirho(&advanced_mount_chirho);
    assert_eq!(
        advanced_status_json_chirho["balance_mount_chirho"]["pinned_chirho"],
        initial_coordinate_chirho
    );
    assert_eq!(
        advanced_status_json_chirho["balance_mount_chirho"]["current_chirho"],
        advanced_coordinate_chirho
    );

    let restarted_chirho =
        load_verified_replica_serve_chirho(&served_chirho.config_chirho, 7_778).unwrap();
    let restarted_url_chirho = start_server_chirho(restarted_chirho.state_chirho);
    let restarted_balance_chirho =
        get_chirho(&format!("{restarted_url_chirho}/view-balance-chirho"));
    assert_eq!(restarted_balance_chirho.0, 200);
    assert!(String::from_utf8(restarted_balance_chirho.1)
        .unwrap()
        .contains(&advanced_mount_chirho.receipt_chirho.view_digest_hex_chirho));
    let restarted_status_chirho =
        get_chirho(&format!("{restarted_url_chirho}/replica-status-chirho"));
    assert_eq!(restarted_status_chirho.0, 200);
    let restarted_status_json_chirho: serde_json::Value =
        serde_json::from_slice(&restarted_status_chirho.1).unwrap();
    assert_eq!(
        restarted_status_json_chirho["balance_mount_chirho"]["restart_required_chirho"],
        false
    );
    assert_eq!(
        restarted_status_json_chirho["balance_mount_chirho"]["pinned_chirho"],
        advanced_coordinate_chirho
    );
    assert_eq!(
        restarted_status_json_chirho["balance_mount_chirho"]["current_chirho"],
        advanced_coordinate_chirho
    );

    std::fs::write(
        advanced_view_path_chirho,
        b"tampered projection bytes chirho",
    )
    .unwrap();
    let tamper_refusal_chirho =
        load_verified_replica_serve_chirho(&served_chirho.config_chirho, 7_779)
            .err()
            .expect("tampered mounted projection bytes must refuse before serving");
    let tamper_message_chirho = format!("{tamper_refusal_chirho:#}");
    assert!(tamper_message_chirho.contains("ProjectionReplicaViewDigestMismatchChirho"));
    assert!(!tamper_message_chirho.contains("ReplicaPublishedOutputHashMismatchChirho"));
}

#[test]
fn running_replica_refuses_an_older_fully_valid_signed_mount_replay_chirho() {
    let served_chirho = served_replica_chirho();
    let (advanced_mount_chirho, _advanced_view_path_chirho) = write_signed_projection_mount_chirho(
        &served_chirho.replica_root_chirho,
        &served_chirho.projection_feeder_root_chirho,
        &served_chirho.projection_identity_chirho,
        &served_chirho.projection_account_chirho,
        8,
        7_777_000,
        'b',
        90,
        7_777,
    );
    assert_eq!(
        advanced_mount_chirho.receipt_chirho.view_digest_hex_chirho,
        served_chirho.initial_projection_digest_chirho,
        "the rollback arm must make the later output-hash gate non-discriminating"
    );
    let advanced_prepared_chirho =
        load_verified_replica_serve_chirho(&served_chirho.config_chirho, 7_778).unwrap();
    let advanced_url_chirho = start_server_chirho(advanced_prepared_chirho.state_chirho);
    let advanced_balance_chirho = get_chirho(&format!("{advanced_url_chirho}/view-balance-chirho"));
    assert_eq!(advanced_balance_chirho.0, 200);
    assert!(String::from_utf8(advanced_balance_chirho.1)
        .unwrap()
        .contains(&advanced_mount_chirho.receipt_chirho.view_digest_hex_chirho));

    // The old mount and its view are canonical, internally consistent, and still signed by the
    // configured feeder. Only the running process's newer full-coordinate pin may refuse it.
    std::fs::write(
        mounted_projection_path_chirho(&served_chirho.replica_root_chirho),
        serde_json::to_vec(&served_chirho.initial_projection_mount_chirho).unwrap(),
    )
    .unwrap();
    let replayed_balance_chirho = get_chirho(&format!("{advanced_url_chirho}/view-balance-chirho"));
    assert_eq!(replayed_balance_chirho.0, 500);
    let replayed_status_chirho =
        get_chirho(&format!("{advanced_url_chirho}/replica-status-chirho"));
    assert_eq!(replayed_status_chirho.0, 200);
    let replayed_status_json_chirho: serde_json::Value =
        serde_json::from_slice(&replayed_status_chirho.1).unwrap();
    assert_eq!(
        replayed_status_json_chirho["balance_mount_chirho"]["restart_required_chirho"],
        true
    );
    assert_eq!(
        replayed_status_json_chirho["balance_mount_chirho"]["pinned_chirho"],
        projection_mount_coordinate_json_chirho(&advanced_mount_chirho)
    );
    assert_eq!(
        replayed_status_json_chirho["balance_mount_chirho"]["current_chirho"],
        projection_mount_coordinate_json_chirho(&served_chirho.initial_projection_mount_chirho)
    );
}

#[test]
fn serve_composition_refuses_an_unrostered_source_before_snapshot_mount_chirho() {
    let replica_root_chirho = tmp_root_chirho("unrostered-replica");
    let operator_root_chirho = tmp_root_chirho("unrostered-operator");
    let rostered_source_root_chirho = tmp_root_chirho("rostered-source");
    let unrostered_source_root_chirho = tmp_root_chirho("unrostered-source");
    let rostered_pubkey_chirho =
        signer_chirho::pubkey_hex_chirho(&rostered_source_root_chirho).unwrap();
    let unrostered_pubkey_chirho =
        signer_chirho::pubkey_hex_chirho(&unrostered_source_root_chirho).unwrap();
    let roster_path_chirho = replica_root_chirho.join("membership-roster-chirho.jsonl");
    let operator_pubkey_chirho = write_single_source_roster_chirho(
        &operator_root_chirho,
        &roster_path_chirho,
        &rostered_pubkey_chirho,
    );
    let error_chirho = load_verified_replica_serve_chirho(
        &ReplicaServeConfigChirho {
            replica_root_chirho: replica_root_chirho.clone(),
            listen_addr_chirho: "127.0.0.1:0".to_string(),
            roster_lines_path_chirho: roster_path_chirho,
            operator_pubkey_hex_chirho: operator_pubkey_chirho,
            source_pubkey_hex_chirho: unrostered_pubkey_chirho,
            allow_public_bind_chirho: false,
            balance_read_chirho: None,
        },
        7_777,
    )
    .err()
    .expect("an operator roster may authorize only its active source keys");
    let message_chirho = format!("{error_chirho:#}");
    assert!(
        message_chirho.contains("ReplicaServeSourceMembershipRefusedChirho"),
        "an unrostered source needs its named refusal: {message_chirho}"
    );
    assert!(
        !message_chirho.contains("ReplicaServeSnapshotLogReadRefusedChirho"),
        "membership must refuse before any snapshot is read: {message_chirho}"
    );

    std::fs::remove_dir_all(replica_root_chirho).unwrap();
    std::fs::remove_dir_all(operator_root_chirho).unwrap();
    std::fs::remove_dir_all(rostered_source_root_chirho).unwrap();
    std::fs::remove_dir_all(unrostered_source_root_chirho).unwrap();
}

/// B2.5(b) — the audit's MEDIUM: a manifest-supplied hash that is not a content address must be
/// refused by the pure gate BEFORE any store read. Each malformed shape renders the SAME uniform
/// 404 as every other refusal (no panic, no 500, no existence oracle).
#[test]
fn malformed_manifest_hashes_never_reach_a_store_read_chirho() {
    let served_chirho = served_replica_chirho();
    let base_chirho = &served_chirho.base_url_chirho;
    let (_status_chirho, uniform_refusal_chirho, _ct_chirho) = get_chirho(&format!(
        "{base_chirho}/runtime-package-chirho/{}/manifest-chirho",
        hash_chirho(b"never deployed").0
    ));
    for manifest_chirho in &served_chirho.malformed_hash_manifests_chirho {
        for route_chirho in ["manifest-chirho", "executable-chirho"] {
            let url_chirho = format!(
                "{base_chirho}/runtime-package-chirho/{}/{route_chirho}",
                manifest_chirho.0
            );
            let (status_chirho, body_chirho, _ct_chirho) = get_chirho(&url_chirho);
            assert_eq!(
                status_chirho, 404,
                "a manifest carrying a non-address hash must refuse, not fault or panic: \
                 {url_chirho}"
            );
            assert_eq!(
                body_chirho, uniform_refusal_chirho,
                "the refusal must be indistinguishable from every other refusal: {url_chirho}"
            );
        }
    }
    // The server is still alive and serving after all of them (no handler panicked the task).
    assert_eq!(get_chirho(&format!("{base_chirho}/healthz-chirho")).0, 200);
}

/// B2.5(c) — the audit's LOW, fault leg: every store fault renders ONE constant body, whatever
/// caused it. Corrupting a replica object drives the store's verify-on-read (M142) failure, which
/// must surface as a generic 500 that never echoes a path-bearing store error.
#[test]
fn store_faults_render_one_constant_body_chirho() {
    let served_chirho = served_replica_chirho();
    let base_chirho = &served_chirho.base_url_chirho;
    let root_chirho = &served_chirho.replica_root_chirho;

    // Fault 1: the EXECUTABLE object's bytes no longer hash to their address.
    let executable_path_chirho = object_path_for_addr_chirho(
        root_chirho,
        &served_chirho.public_package_chirho.executable_chirho,
    );
    std::fs::write(&executable_path_chirho, b"tampered replica bytes").unwrap();
    let (status_chirho, fault_body_chirho, _ct_chirho) = get_chirho(&format!(
        "{base_chirho}/runtime-package-chirho/{}/executable-chirho",
        served_chirho.public_manifest_chirho.0
    ));
    assert_eq!(
        status_chirho, 500,
        "a tampered object must fault, never serve"
    );
    let rendered_chirho = String::from_utf8_lossy(&fault_body_chirho).to_string();
    assert!(
        !rendered_chirho.contains("objects-chirho")
            && !rendered_chirho.contains(&root_chirho.display().to_string()),
        "the fault body must never echo a path-bearing store error: {rendered_chirho}"
    );

    // Fault 2: a DIFFERENT cause (the MANIFEST object itself is corrupt) renders the IDENTICAL
    // body — the fault surface says nothing about which object failed.
    let manifest_path_chirho =
        object_path_for_addr_chirho(root_chirho, &served_chirho.public_manifest_chirho);
    std::fs::write(&manifest_path_chirho, b"tampered manifest bytes").unwrap();
    let (status_chirho, second_fault_chirho, _ct_chirho) = get_chirho(&format!(
        "{base_chirho}/runtime-package-chirho/{}/manifest-chirho",
        served_chirho.public_manifest_chirho.0
    ));
    assert_eq!(status_chirho, 500);
    assert_eq!(
        second_fault_chirho, fault_body_chirho,
        "every store fault must render the identical constant body"
    );
}

/// B2.5(a) — the audit's HIGH: pre-commitment (e) is an ALLOWLIST. Loopback and private/mesh
/// addresses bind freely; wildcards (including the IPv4-mapped spelling that the old
/// `is_unspecified()` check missed) and routable public addresses are refused without the explicit
/// public-exposure flag.
#[test]
fn bind_guard_allows_only_loopback_and_private_addresses_chirho() {
    for allowed_chirho in [
        "127.0.0.1:0",
        "[::1]:0",
        "10.100.0.1:0",  // the WireGuard mesh
        "192.168.1.5:0", // RFC1918
        "172.16.0.9:0",  // RFC1918
        "[fd00::1]:0",   // IPv6 unique-local
    ] {
        // Binding may still fail because this host does not own the address — what must NOT happen
        // is a refusal by the GUARD. Distinguish by the message the guard uses.
        if let Err(error_chirho) = bind_replica_listener_chirho(allowed_chirho, false) {
            let message_chirho = error_chirho.to_string();
            assert!(
                !message_chirho.contains("refuses this bind address"),
                "the guard must permit the private/loopback address {allowed_chirho}: \
                 {message_chirho}"
            );
        }
    }
    for refused_chirho in [
        "0.0.0.0:0",                // the IPv4 wildcard
        "[::]:0",                   // the IPv6 wildcard
        "[::ffff:0.0.0.0]:0",       // the IPv4-MAPPED wildcard — the audit's reproduced bypass
        "8.8.8.8:0",                // a routable public address (bindable on a host that owns it)
        "[::ffff:8.8.8.8]:0",       // its IPv4-mapped spelling
        "[2001:4860:4860::8888]:0", // a routable public IPv6 address
    ] {
        let message_chirho = bind_replica_listener_chirho(refused_chirho, false)
            .expect_err(&format!(
                "public exposure is a separate approval: {refused_chirho} must be refused"
            ))
            .to_string();
        assert!(
            message_chirho.contains("refuses this bind address"),
            "{refused_chirho} must be refused by the GUARD (not merely fail to bind): \
             {message_chirho}"
        );
    }
    // The explicit opt-in still works (that is the approved-exposure path), and a malformed
    // address is refused on both settings.
    assert!(bind_replica_listener_chirho("0.0.0.0:0", true).is_ok());
    assert!(bind_replica_listener_chirho("not-an-addr", false).is_err());
    assert!(bind_replica_listener_chirho("not-an-addr", true).is_err());
}

#[test]
fn serves_the_public_contract_and_refuses_everything_else_chirho() {
    let served_chirho = served_replica_chirho();
    let base_chirho = &served_chirho.base_url_chirho;

    // Health + staleness evidence (pre-commitment d on the serve surface).
    assert_eq!(get_chirho(&format!("{base_chirho}/healthz-chirho")).0, 200);
    let (status_chirho, body_chirho, content_type_chirho) =
        get_chirho(&format!("{base_chirho}/replica-status-chirho"));
    assert_eq!(status_chirho, 200);
    assert_eq!(content_type_chirho, "application/json");
    let status_json_chirho: serde_json::Value = serde_json::from_slice(&body_chirho).unwrap();
    assert_eq!(status_json_chirho["seq_chirho"], 1);
    assert_eq!(status_json_chirho["source_time_unix_chirho"], 1_000);
    assert_eq!(status_json_chirho["verified_at_unix_chirho"], 7_777);
    assert_eq!(
        status_json_chirho["decision_chirho"],
        "IdempotentRemountChirho"
    );

    // Discovery: exactly the snapshot's refs.
    let (_status_chirho, apps_body_chirho, _ct_chirho) =
        get_chirho(&format!("{base_chirho}/replica-apps-chirho"));
    let apps_chirho: BTreeMap<String, String> = serde_json::from_slice(&apps_body_chirho).unwrap();
    assert_eq!(
        apps_chirho.get("app/demo"),
        Some(&served_chirho.public_manifest_chirho.0)
    );
    assert_eq!(apps_chirho.len(), 2);

    // The public package: stored manifest bytes verbatim, then the executable bytes.
    let manifest_url_chirho = format!(
        "{base_chirho}/runtime-package-chirho/{}/manifest-chirho",
        served_chirho.public_manifest_chirho.0
    );
    let (status_chirho, manifest_body_chirho, content_type_chirho) =
        get_chirho(&manifest_url_chirho);
    assert_eq!(status_chirho, 200);
    assert_eq!(content_type_chirho, "application/json");
    let round_chirho: RuntimePackageChirho = serde_json::from_slice(&manifest_body_chirho).unwrap();
    assert_eq!(round_chirho, served_chirho.public_package_chirho);
    let (status_chirho, wasm_body_chirho, content_type_chirho) = get_chirho(&format!(
        "{base_chirho}/runtime-package-chirho/{}/executable-chirho",
        served_chirho.public_manifest_chirho.0
    ));
    assert_eq!(status_chirho, 200);
    assert_eq!(content_type_chirho, "application/wasm");
    assert_eq!(wasm_body_chirho, served_chirho.wasm_chirho);

    // The refusal matrix renders ONE uniform 404 on both routes: server-profile,
    // capability-bearing, extra-object, absent, and malformed hashes are indistinguishable.
    // B2.5(c): status alone is not non-leak — the BODY must be byte-identical across every
    // refusal, or the response itself tells an unauthorized caller WHICH refusal it hit.
    let mut refused_urls_chirho: Vec<String> = Vec::new();
    for manifest_chirho in &served_chirho.refused_manifests_chirho {
        refused_urls_chirho.push(format!(
            "{base_chirho}/runtime-package-chirho/{}/manifest-chirho",
            manifest_chirho.0
        ));
        refused_urls_chirho.push(format!(
            "{base_chirho}/runtime-package-chirho/{}/executable-chirho",
            manifest_chirho.0
        ));
    }
    refused_urls_chirho.push(format!(
        "{base_chirho}/runtime-package-chirho/{}/manifest-chirho",
        hash_chirho(b"never deployed").0
    ));
    refused_urls_chirho.push(format!(
        "{base_chirho}/runtime-package-chirho/not-a-hash/manifest-chirho"
    ));
    let mut refusal_bodies_chirho: Vec<Vec<u8>> = Vec::new();
    for url_chirho in refused_urls_chirho {
        let (status_chirho, body_chirho, _ct_chirho) = get_chirho(&url_chirho);
        assert_eq!(status_chirho, 404, "{url_chirho}");
        refusal_bodies_chirho.push(body_chirho);
    }
    let first_body_chirho = refusal_bodies_chirho
        .first()
        .expect("the refusal matrix is non-empty")
        .clone();
    for body_chirho in &refusal_bodies_chirho {
        assert_eq!(
            body_chirho, &first_body_chirho,
            "every refusal must render the IDENTICAL body — a distinct body leaks which check \
             refused (absent vs non-public vs malformed)"
        );
    }

    // The ghost (not-replicated executable): manifest passes the pure gate, bytes 404 honestly.
    assert_eq!(
        get_chirho(&format!(
            "{base_chirho}/runtime-package-chirho/{}/manifest-chirho",
            served_chirho.ghost_manifest_chirho.0
        ))
        .0,
        200
    );
    assert_eq!(
        get_chirho(&format!(
            "{base_chirho}/runtime-package-chirho/{}/executable-chirho",
            served_chirho.ghost_manifest_chirho.0
        ))
        .0,
        404
    );

    // GET-only surface: a mutation attempt on every route is a 405, never a handler.
    for path_chirho in [
        "/replica-status-chirho".to_string(),
        "/replica-apps-chirho".to_string(),
        format!(
            "/runtime-package-chirho/{}/manifest-chirho",
            served_chirho.public_manifest_chirho.0
        ),
    ] {
        match ureq::AgentBuilder::new()
            .redirects(0)
            .build()
            .post(&format!("{base_chirho}{path_chirho}"))
            .send_string("mutate")
        {
            Err(ureq::Error::Status(405, _)) => {}
            other_chirho => panic!("POST {path_chirho} must 405, got {other_chirho:?}"),
        }
    }
}
