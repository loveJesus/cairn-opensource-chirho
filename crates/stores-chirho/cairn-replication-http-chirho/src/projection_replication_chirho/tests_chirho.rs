// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::model_chirho::{
    decode_and_verify_receipt_chirho, decode_and_verify_view_chirho, validate_pull_config_chirho,
    validate_source_config_chirho, ProjectionReplicaPullConfigChirho,
    ProjectionReplicaPullDispositionChirho, ProjectionReplicationIdentityChirho,
    ProjectionReplicationSourceConfigChirho,
};
use super::pull_chirho::{
    classify_receipt_advance_chirho, mounted_projection_path_chirho,
    pull_and_mount_projection_chirho, read_verified_mounted_projection_chirho,
};
use super::replica_read_chirho::ReplicaMountedProjectionReadPortChirho;
use super::source_chirho::{
    projection_replication_router_chirho, serve_projection_router_blocking_chirho,
    FsProjectionReplicationSourceChirho,
};
use super::{
    projection_head_url_chirho, projection_view_url_chirho, PROJECTION_REPLICATION_HEAD_PATH_CHIRHO,
};
use crate::read_dag_chirho::{ReplicaBalanceReadDagChirho, ReplicaBalanceReadDagRunnerChirho};
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
    follow_receipt_signed_content_chirho, view_bytes_digest_hex_chirho, FollowReceiptChirho,
    FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_read_model_chirho::publication_chirho::view_cas_path_chirho;
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const TEST_BEARER_CHIRHO: &str = "projection-replica-test-bearer-chirho";
const TEST_PROJECTION_CHIRHO: &str = "credits-balance-chirho";
const TEST_CLUSTER_CHIRHO: &str = "credits-demo-cluster-chirho";
const TEST_HEAD_CHIRHO: &str = "published/credits-balance-head-chirho.json";

struct FixtureChirho {
    root_chirho: PathBuf,
    source_root_chirho: PathBuf,
    replica_root_chirho: PathBuf,
    signer_root_chirho: PathBuf,
    identity_chirho: ProjectionReplicationIdentityChirho,
    account_chirho: LogIdChirho,
    bearer_env_chirho: String,
}

impl FixtureChirho {
    fn new_chirho(label_chirho: &str) -> Self {
        let root_chirho = temp_root_chirho(label_chirho);
        let source_root_chirho = root_chirho.join("source-chirho");
        let replica_root_chirho = root_chirho.join("replica-chirho");
        let signer_root_chirho = root_chirho.join("feeder-key-chirho");
        std::fs::create_dir_all(source_root_chirho.join("published")).unwrap();
        std::fs::create_dir_all(source_root_chirho.join("projections/views-chirho")).unwrap();
        let feeder_pubkey_hex_chirho = pubkey_hex_chirho(&signer_root_chirho).unwrap();
        let identity_chirho = ProjectionReplicationIdentityChirho {
            projection_name_chirho: TEST_PROJECTION_CHIRHO.to_owned(),
            descriptor_digest_chirho: "1".repeat(64),
            source_cluster_chirho: TEST_CLUSTER_CHIRHO.to_owned(),
            source_genesis_digest_chirho: "2".repeat(64),
            feeder_pubkey_hex_chirho,
        };
        let account_chirho = LogIdChirho::new_chirho(
            "synthetic-payer-chirho",
            AssetKindIdChirho("credits-chirho".to_owned()),
        );
        let bearer_env_chirho = format!(
            "CAIRN_PROJECTION_REPLICA_TEST_BEARER_{}_CHIRHO",
            root_chirho
                .file_name()
                .unwrap()
                .to_string_lossy()
                .replace('-', "_")
        );
        std::env::set_var(&bearer_env_chirho, TEST_BEARER_CHIRHO);
        Self {
            root_chirho,
            source_root_chirho,
            replica_root_chirho,
            signer_root_chirho,
            identity_chirho,
            account_chirho,
            bearer_env_chirho,
        }
    }

    fn source_config_chirho(&self) -> ProjectionReplicationSourceConfigChirho {
        ProjectionReplicationSourceConfigChirho {
            source_namespace_root_chirho: self.source_root_chirho.clone(),
            head_path_chirho: TEST_HEAD_CHIRHO.to_owned(),
            listen_addr_chirho: "127.0.0.1:0".to_owned(),
            bearer_env_chirho: self.bearer_env_chirho.clone(),
            identity_chirho: self.identity_chirho.clone(),
        }
    }

    fn pull_config_chirho(&self, source_url_chirho: &str) -> ProjectionReplicaPullConfigChirho {
        ProjectionReplicaPullConfigChirho {
            source_url_chirho: source_url_chirho.to_owned(),
            bearer_env_chirho: self.bearer_env_chirho.clone(),
            replica_root_chirho: self.replica_root_chirho.clone(),
            identity_chirho: self.identity_chirho.clone(),
            inspect_accounts_chirho: vec![self.account_chirho.clone()],
        }
    }

    fn publish_chirho(
        &self,
        sequence_chirho: u64,
        physical_ms_chirho: u64,
        account_net_chirho: u64,
        tail_digit_chirho: char,
    ) -> (FollowReceiptChirho, Vec<u8>) {
        let view_chirho = AccountNetProjectionViewChirho {
            schema_chirho: ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO.to_owned(),
            rows_chirho: vec![AccountNetProjectionRowChirho {
                account_chirho: self.account_chirho.clone(),
                account_net_chirho,
            }],
        };
        let view_bytes_chirho = canonical_account_net_projection_view_chirho(&view_chirho).unwrap();
        let mut receipt_chirho = FollowReceiptChirho {
            schema_chirho: FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO.to_owned(),
            projection_name_chirho: self.identity_chirho.projection_name_chirho.clone(),
            descriptor_digest_chirho: DigestChirho(
                self.identity_chirho.descriptor_digest_chirho.clone(),
            ),
            source_cluster_chirho: self.identity_chirho.source_cluster_chirho.clone(),
            source_genesis_digest_chirho: DigestChirho(
                self.identity_chirho.source_genesis_digest_chirho.clone(),
            ),
            source_tail_seq_chirho: sequence_chirho,
            source_tail_hlc_chirho: HlcChirho {
                physical_ms_chirho,
                logical_chirho: 0,
            },
            source_tail_line_digest_chirho: DigestChirho(tail_digit_chirho.to_string().repeat(64)),
            view_digest_hex_chirho: view_bytes_digest_hex_chirho(&view_bytes_chirho),
            feeder_sig_chirho: String::new(),
        };
        let signed_content_chirho = follow_receipt_signed_content_chirho(&receipt_chirho).unwrap();
        receipt_chirho.feeder_sig_chirho =
            sign_message_chirho(&self.signer_root_chirho, signed_content_chirho.as_bytes())
                .unwrap();
        let view_path_chirho = self
            .source_root_chirho
            .join(view_cas_path_chirho(&receipt_chirho.view_digest_hex_chirho).0);
        std::fs::write(view_path_chirho, &view_bytes_chirho).unwrap();
        std::fs::write(
            self.source_root_chirho.join(TEST_HEAD_CHIRHO),
            serde_json::to_vec(&receipt_chirho).unwrap(),
        )
        .unwrap();
        (receipt_chirho, view_bytes_chirho)
    }

    fn start_source_chirho(&self) -> String {
        let source_chirho = Arc::new(
            FsProjectionReplicationSourceChirho::open_existing_chirho(&self.source_config_chirho())
                .unwrap(),
        );
        let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let source_url_chirho = format!("http://{}", listener_chirho.local_addr().unwrap());
        let router_chirho =
            projection_replication_router_chirho(source_chirho, TEST_BEARER_CHIRHO.to_owned());
        std::thread::spawn(move || {
            let _result_chirho =
                serve_projection_router_blocking_chirho(listener_chirho, router_chirho);
        });
        source_url_chirho
    }
}

impl Drop for FixtureChirho {
    fn drop(&mut self) {
        std::env::remove_var(&self.bearer_env_chirho);
        let _remove_chirho = std::fs::remove_dir_all(&self.root_chirho);
    }
}

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "projection-replica-{label_chirho}-{}-{counter_chirho}",
        std::process::id()
    ));
    let _remove_chirho = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

#[test]
fn pull_mounts_advances_and_idempotently_reobserves_one_signed_view_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho("advance");
    let (first_receipt_chirho, _first_view_chirho) =
        fixture_chirho.publish_chirho(7, 1_000, 90, 'a');
    let source_url_chirho = fixture_chirho.start_source_chirho();
    let config_chirho = fixture_chirho.pull_config_chirho(&source_url_chirho);

    let first_report_chirho = pull_and_mount_projection_chirho(&config_chirho, 10).unwrap();
    assert_eq!(
        first_report_chirho.disposition_chirho,
        ProjectionReplicaPullDispositionChirho::InstalledInitialChirho
    );
    assert_eq!(
        first_report_chirho.inspected_accounts_chirho[0].account_net_chirho,
        90
    );
    let same_report_chirho = pull_and_mount_projection_chirho(&config_chirho, 11).unwrap();
    assert_eq!(
        same_report_chirho.disposition_chirho,
        ProjectionReplicaPullDispositionChirho::AlreadyCurrentChirho
    );

    let (second_receipt_chirho, _second_view_chirho) =
        fixture_chirho.publish_chirho(8, 1_010, 80, 'b');
    let second_report_chirho = pull_and_mount_projection_chirho(&config_chirho, 12).unwrap();
    assert_eq!(
        second_report_chirho.disposition_chirho,
        ProjectionReplicaPullDispositionChirho::AdvancedChirho
    );
    assert_eq!(
        second_report_chirho.inspected_accounts_chirho[0].account_net_chirho,
        80
    );
    assert_ne!(
        first_receipt_chirho.view_digest_hex_chirho,
        second_receipt_chirho.view_digest_hex_chirho
    );
    let (mounted_chirho, mounted_view_chirho) =
        read_verified_mounted_projection_chirho(&config_chirho).unwrap();
    assert_eq!(mounted_chirho.receipt_chirho, second_receipt_chirho);
    assert_eq!(mounted_chirho.mounted_at_unix_chirho, 12);
    assert_eq!(mounted_view_chirho.rows_chirho[0].account_net_chirho, 80);
}

#[test]
fn mounted_projection_port_is_degraded_and_refuses_wrong_projection_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho("read-port");
    fixture_chirho.publish_chirho(7, 1_000, 90, 'a');
    let source_url_chirho = fixture_chirho.start_source_chirho();
    let config_chirho = fixture_chirho.pull_config_chirho(&source_url_chirho);
    pull_and_mount_projection_chirho(&config_chirho, 1_100).unwrap();
    let port_chirho =
        ReplicaMountedProjectionReadPortChirho::new_chirho(config_chirho.clone(), 1_100, 100);
    let read_chirho = port_chirho
        .read_published_projection_chirho(TEST_PROJECTION_CHIRHO, 1)
        .unwrap();
    assert_eq!(read_chirho.lag_ms_chirho, 100);
    assert_eq!(read_chirho.max_lag_ms_chirho, 100);
    let wrong_projection_chirho = port_chirho
        .read_published_projection_chirho("other-projection-chirho", 1)
        .unwrap_err();
    assert!(wrong_projection_chirho
        .to_string()
        .contains("ReplicaProjectionNameRefusedChirho"));
}

#[test]
fn pinned_direct_mount_refuses_a_valid_same_view_source_advance_until_restart_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho("pinned-direct-mount");
    let (first_receipt_chirho, first_view_bytes_chirho) =
        fixture_chirho.publish_chirho(7, 1_000, 90, 'a');
    let source_url_chirho = fixture_chirho.start_source_chirho();
    let config_chirho = fixture_chirho.pull_config_chirho(&source_url_chirho);
    pull_and_mount_projection_chirho(&config_chirho, 1_100).unwrap();

    let first_port_chirho =
        ReplicaMountedProjectionReadPortChirho::new_chirho(config_chirho.clone(), 1_100, 100);
    let first_coordinate_chirho = first_port_chirho.current_mount_coordinate_chirho().unwrap();
    let first_dag_chirho = ReplicaBalanceReadDagRunnerChirho::direct_verified_mount_dag_chirho(
        &first_coordinate_chirho,
    );
    let first_runner_chirho = ReplicaBalanceReadDagRunnerChirho::new_pinned_chirho(
        first_port_chirho,
        first_coordinate_chirho.clone(),
    );
    let store_chirho = cairn_store_fs_chirho::FsContentStoreChirho::new_chirho(
        &fixture_chirho.replica_root_chirho,
    );
    let first_result_chirho = first_runner_chirho
        .run_chirho(&store_chirho, &first_dag_chirho, b"request")
        .unwrap()
        .unwrap();
    assert_eq!(first_result_chirho.bytes_chirho, first_view_bytes_chirho);
    assert_eq!(
        first_result_chirho.output_hash_chirho.0,
        first_receipt_chirho.view_digest_hex_chirho
    );

    // The view is deliberately byte-identical. A digest-only process pin would miss this valid
    // signed source-cut advance and silently keep serving under a coordinate it never reviewed.
    let (second_receipt_chirho, second_view_bytes_chirho) =
        fixture_chirho.publish_chirho(8, 1_010, 90, 'b');
    assert_eq!(first_view_bytes_chirho, second_view_bytes_chirho);
    assert_eq!(
        first_receipt_chirho.view_digest_hex_chirho,
        second_receipt_chirho.view_digest_hex_chirho
    );
    pull_and_mount_projection_chirho(&config_chirho, 1_101).unwrap();

    let refusal_chirho = first_runner_chirho
        .run_chirho(&store_chirho, &first_dag_chirho, b"request")
        .expect_err("a running process must not silently follow a valid later source cut");
    let refusal_message_chirho = refusal_chirho.to_string();
    assert!(refusal_message_chirho.contains("ReplicaProjectionMountCoordinateMismatchChirho"));
    assert!(!refusal_message_chirho.contains("ReplicaPublishedOutputHashMismatchChirho"));

    let second_port_chirho =
        ReplicaMountedProjectionReadPortChirho::new_chirho(config_chirho, 1_101, 101);
    let second_coordinate_chirho = second_port_chirho
        .current_mount_coordinate_chirho()
        .unwrap();
    assert_ne!(first_coordinate_chirho, second_coordinate_chirho);
    assert_eq!(
        second_coordinate_chirho.view_digest_hex_chirho,
        first_coordinate_chirho.view_digest_hex_chirho
    );
    let second_dag_chirho = ReplicaBalanceReadDagRunnerChirho::direct_verified_mount_dag_chirho(
        &second_coordinate_chirho,
    );
    let second_runner_chirho = ReplicaBalanceReadDagRunnerChirho::new_pinned_chirho(
        second_port_chirho,
        second_coordinate_chirho,
    );
    let second_result_chirho = second_runner_chirho
        .run_chirho(&store_chirho, &second_dag_chirho, b"request")
        .unwrap()
        .unwrap();
    assert_eq!(second_result_chirho.bytes_chirho, second_view_bytes_chirho);
}

#[test]
fn read_dag_runner_hash_mismatch_arm_reaches_the_runner_call_site_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho("read-dag-hash");
    fixture_chirho.publish_chirho(7, 1_000, 90, 'a');
    let source_url_chirho = fixture_chirho.start_source_chirho();
    let config_chirho = fixture_chirho.pull_config_chirho(&source_url_chirho);
    pull_and_mount_projection_chirho(&config_chirho, 1_100).unwrap();
    let port_chirho =
        ReplicaMountedProjectionReadPortChirho::new_chirho(config_chirho.clone(), 1_100, 100);
    let runner_chirho = ReplicaBalanceReadDagRunnerChirho::new_chirho(port_chirho);
    let view_bytes_chirho =
        ReplicaMountedProjectionReadPortChirho::new_chirho(config_chirho.clone(), 1_100, 100)
            .read_published_projection_chirho(TEST_PROJECTION_CHIRHO, 1)
            .unwrap()
            .view_bytes_chirho;
    let wasm_chirho = wat::parse_bytes(include_bytes!(
        "../../../../../examples-chirho/upcase-chirho.wat"
    ))
    .unwrap();
    let wasm_object_hash_chirho = cairn_store_fs_chirho::FsContentStoreChirho::new_chirho(
        &fixture_chirho.replica_root_chirho,
    )
    .put_chirho(&wasm_chirho)
    .unwrap();
    let schema_hash_chirho = HashChirho("1".repeat(64));
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
    let node_hash_chirho = cairn_store_fs_chirho::FsContentStoreChirho::new_chirho(
        &fixture_chirho.replica_root_chirho,
    )
    .put_chirho(&serde_json::to_vec(&node_chirho).unwrap())
    .unwrap();
    let post_dag_chirho = DagChirho {
        nodes_chirho: vec![node_hash_chirho],
        edges_chirho: Vec::new(),
    };
    let positive_dag_chirho = ReplicaBalanceReadDagChirho {
        before_query_dag_chirho: None,
        after_query_dag_chirho: Some(post_dag_chirho.clone()),
        expected_output_hash_chirho: HashChirho(
            blake3::hash(&view_bytes_chirho.to_ascii_uppercase())
                .to_hex()
                .to_string(),
        ),
    };
    let positive_result_chirho = ReplicaBalanceReadDagRunnerChirho::new_chirho(
        ReplicaMountedProjectionReadPortChirho::new_chirho(config_chirho.clone(), 1_100, 100),
    )
    .run_chirho(
        &cairn_store_fs_chirho::FsContentStoreChirho::new_chirho(
            &fixture_chirho.replica_root_chirho,
        ),
        &positive_dag_chirho,
        b"request",
    )
    .unwrap()
    .unwrap();
    assert_ne!(
        positive_result_chirho.output_hash_chirho,
        HashChirho("0".repeat(64))
    );
    assert_ne!(
        positive_result_chirho.output_hash_chirho,
        HashChirho(blake3::hash(&view_bytes_chirho).to_hex().to_string(),)
    );
    let dag_chirho = ReplicaBalanceReadDagChirho {
        before_query_dag_chirho: None,
        after_query_dag_chirho: Some(post_dag_chirho),
        expected_output_hash_chirho: HashChirho("0".repeat(64)),
    };
    let store_chirho = cairn_store_fs_chirho::FsContentStoreChirho::new_chirho(
        &fixture_chirho.replica_root_chirho,
    );
    let error_chirho = runner_chirho
        .run_chirho(&store_chirho, &dag_chirho, b"request")
        .expect_err("the full runner must reach the published hash gate");
    assert!(error_chirho
        .to_string()
        .contains("ReplicaPublishedOutputHashMismatchChirho"));
}

#[test]
fn rollback_and_same_sequence_equivocation_refuse_before_mount_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho("floor");
    let (initial_receipt_chirho, _initial_view_chirho) =
        fixture_chirho.publish_chirho(9, 2_000, 70, 'c');
    let source_url_chirho = fixture_chirho.start_source_chirho();
    let config_chirho = fixture_chirho.pull_config_chirho(&source_url_chirho);
    pull_and_mount_projection_chirho(&config_chirho, 20).unwrap();

    let (rollback_receipt_chirho, _rollback_view_chirho) =
        fixture_chirho.publish_chirho(8, 1_999, 80, 'b');
    let rollback_chirho = pull_and_mount_projection_chirho(&config_chirho, 21).unwrap_err();
    assert!(rollback_chirho
        .to_string()
        .contains("ProjectionReplicaRollbackRefusedChirho"));
    assert!(!rollback_chirho
        .to_string()
        .contains("ProjectionReplicaSameSequenceEquivocationRefusedChirho"));

    let (equivocating_receipt_chirho, _equivocating_view_chirho) =
        fixture_chirho.publish_chirho(9, 2_000, 60, 'd');
    let equivocation_chirho = pull_and_mount_projection_chirho(&config_chirho, 22).unwrap_err();
    assert!(equivocation_chirho
        .to_string()
        .contains("ProjectionReplicaSameSequenceEquivocationRefusedChirho"));
    assert!(!equivocation_chirho
        .to_string()
        .contains("ProjectionReplicaRollbackRefusedChirho"));
    let (mounted_chirho, _mounted_view_chirho) =
        read_verified_mounted_projection_chirho(&config_chirho).unwrap();
    assert_eq!(mounted_chirho.receipt_chirho, initial_receipt_chirho);
    assert_ne!(rollback_receipt_chirho, initial_receipt_chirho);
    assert_ne!(equivocating_receipt_chirho, initial_receipt_chirho);
}

#[test]
fn receipt_identity_signature_and_view_bytes_are_independently_verified_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho("verification");
    let (receipt_chirho, view_bytes_chirho) = fixture_chirho.publish_chirho(3, 300, 40, 'e');
    let receipt_bytes_chirho = serde_json::to_vec(&receipt_chirho).unwrap();
    assert!(decode_and_verify_receipt_chirho(
        &receipt_bytes_chirho,
        &fixture_chirho.identity_chirho
    )
    .is_ok());

    let mut wrong_identity_chirho = fixture_chirho.identity_chirho.clone();
    wrong_identity_chirho.source_cluster_chirho = "foreign-cluster-chirho".to_owned();
    let wrong_cluster_chirho =
        decode_and_verify_receipt_chirho(&receipt_bytes_chirho, &wrong_identity_chirho)
            .unwrap_err();
    assert!(wrong_cluster_chirho
        .to_string()
        .contains("ProjectionReplicaSourceClusterMismatchChirho"));
    assert!(!wrong_cluster_chirho
        .to_string()
        .contains("ProjectionReplicaReceiptSignatureRefusedChirho"));

    let mut forged_receipt_chirho = receipt_chirho.clone();
    let replacement_chirho = if forged_receipt_chirho.feeder_sig_chirho.starts_with('0') {
        "1"
    } else {
        "0"
    };
    forged_receipt_chirho
        .feeder_sig_chirho
        .replace_range(0..1, replacement_chirho);
    let forged_chirho = decode_and_verify_receipt_chirho(
        &serde_json::to_vec(&forged_receipt_chirho).unwrap(),
        &fixture_chirho.identity_chirho,
    )
    .unwrap_err();
    assert!(forged_chirho
        .to_string()
        .contains("ProjectionReplicaReceiptSignatureRefusedChirho"));
    assert!(!forged_chirho
        .to_string()
        .contains("ProjectionReplicaSourceClusterMismatchChirho"));

    let mut divergent_view_chirho = view_bytes_chirho.clone();
    divergent_view_chirho.push(b' ');
    let digest_chirho = decode_and_verify_view_chirho(
        &divergent_view_chirho,
        &receipt_chirho.view_digest_hex_chirho,
    )
    .unwrap_err();
    assert!(digest_chirho
        .to_string()
        .contains("ProjectionReplicaViewDigestMismatchChirho"));
    assert!(!digest_chirho
        .to_string()
        .contains("ProjectionReplicaViewCanonicalRefusedChirho"));

    let noncanonical_view_chirho = serde_json::to_vec_pretty(
        &serde_json::from_slice::<serde_json::Value>(&view_bytes_chirho).unwrap(),
    )
    .unwrap();
    let noncanonical_digest_chirho = view_bytes_digest_hex_chirho(&noncanonical_view_chirho);
    let canonical_chirho =
        decode_and_verify_view_chirho(&noncanonical_view_chirho, &noncanonical_digest_chirho)
            .unwrap_err();
    assert!(canonical_chirho
        .to_string()
        .contains("ProjectionReplicaViewCanonicalRefusedChirho"));
    assert!(!canonical_chirho
        .to_string()
        .contains("ProjectionReplicaViewDigestMismatchChirho"));
}

#[test]
fn source_requires_bearer_and_exposes_no_arbitrary_path_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho("wire");
    let (receipt_chirho, _view_chirho) = fixture_chirho.publish_chirho(1, 100, 100, 'f');
    let source_url_chirho = fixture_chirho.start_source_chirho();
    let agent_chirho = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .redirects(0)
        .build();

    match agent_chirho
        .get(&projection_head_url_chirho(&source_url_chirho))
        .call()
    {
        Err(ureq::Error::Status(401, response_chirho)) => {
            assert_eq!(
                response_chirho.into_string().unwrap(),
                "ProjectionReplicaBearerRefusedChirho"
            );
        }
        other_chirho => panic!("missing bearer must refuse: {other_chirho:?}"),
    }
    let head_chirho = agent_chirho
        .get(&projection_head_url_chirho(&source_url_chirho))
        .set("Authorization", &format!("Bearer {TEST_BEARER_CHIRHO}"))
        .call()
        .unwrap();
    assert_eq!(head_chirho.status(), 200);

    let arbitrary_chirho =
        format!("{source_url_chirho}/replication-chirho/projection-chirho/private-key-chirho");
    match agent_chirho.get(&arbitrary_chirho).call() {
        Err(ureq::Error::Status(404, _response_chirho)) => {}
        other_chirho => panic!("an arbitrary path must not be routed: {other_chirho:?}"),
    }
    let stale_view_chirho = projection_view_url_chirho(&source_url_chirho, &"0".repeat(64));
    match agent_chirho
        .get(&stale_view_chirho)
        .set("Authorization", &format!("Bearer {TEST_BEARER_CHIRHO}"))
        .call()
    {
        Err(ureq::Error::Status(409, response_chirho)) => {
            assert_eq!(
                response_chirho.into_string().unwrap(),
                "ProjectionReplicaViewNotCurrentRefusedChirho"
            );
        }
        other_chirho => panic!("a non-current view must refuse: {other_chirho:?}"),
    }
    assert_eq!(
        PROJECTION_REPLICATION_HEAD_PATH_CHIRHO,
        "/replication-chirho/projection-chirho/head-chirho"
    );
    assert_eq!(
        receipt_chirho.view_digest_hex_chirho.len(),
        64,
        "the fixture must carry a real digest so the stale-view control is discriminating"
    );
}

#[test]
fn source_clock_regression_and_reused_tail_refuse_even_with_higher_sequence_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho("monotonic");
    let (prior_chirho, _prior_view_chirho) = fixture_chirho.publish_chirho(5, 500, 50, 'a');
    let (clock_regression_chirho, _clock_view_chirho) =
        fixture_chirho.publish_chirho(6, 499, 49, 'b');
    let clock_error_chirho =
        classify_receipt_advance_chirho(Some(&prior_chirho), &clock_regression_chirho).unwrap_err();
    assert!(clock_error_chirho
        .to_string()
        .contains("ProjectionReplicaSourceClockRegressionRefusedChirho"));
    assert!(!clock_error_chirho
        .to_string()
        .contains("ProjectionReplicaSourceTailDidNotAdvanceRefusedChirho"));

    let mut reused_tail_chirho = clock_regression_chirho;
    reused_tail_chirho.source_tail_hlc_chirho.physical_ms_chirho = 501;
    reused_tail_chirho.source_tail_line_digest_chirho =
        prior_chirho.source_tail_line_digest_chirho.clone();
    let tail_error_chirho =
        classify_receipt_advance_chirho(Some(&prior_chirho), &reused_tail_chirho).unwrap_err();
    assert!(tail_error_chirho
        .to_string()
        .contains("ProjectionReplicaSourceTailDidNotAdvanceRefusedChirho"));
    assert!(!tail_error_chirho
        .to_string()
        .contains("ProjectionReplicaSourceClockRegressionRefusedChirho"));
}

#[test]
fn corrupt_prior_mount_or_missing_bound_view_refuses_before_advance_chirho() {
    let corrupt_fixture_chirho = FixtureChirho::new_chirho("corrupt-mount");
    corrupt_fixture_chirho.publish_chirho(1, 100, 100, 'a');
    let corrupt_source_url_chirho = corrupt_fixture_chirho.start_source_chirho();
    let corrupt_config_chirho =
        corrupt_fixture_chirho.pull_config_chirho(&corrupt_source_url_chirho);
    pull_and_mount_projection_chirho(&corrupt_config_chirho, 1).unwrap();
    std::fs::write(
        mounted_projection_path_chirho(&corrupt_fixture_chirho.replica_root_chirho),
        b"not-a-canonical-mount-chirho",
    )
    .unwrap();
    corrupt_fixture_chirho.publish_chirho(2, 101, 90, 'b');
    let corrupt_error_chirho =
        pull_and_mount_projection_chirho(&corrupt_config_chirho, 2).unwrap_err();
    assert!(corrupt_error_chirho
        .to_string()
        .contains("ProjectionReplicaMountDecodeRefusedChirho"));
    assert!(!corrupt_error_chirho
        .to_string()
        .contains("ProjectionReplicaViewFetchRefusedChirho"));

    let missing_fixture_chirho = FixtureChirho::new_chirho("missing-view");
    let (mounted_receipt_chirho, _mounted_view_chirho) =
        missing_fixture_chirho.publish_chirho(1, 100, 100, 'c');
    let missing_source_url_chirho = missing_fixture_chirho.start_source_chirho();
    let missing_config_chirho =
        missing_fixture_chirho.pull_config_chirho(&missing_source_url_chirho);
    pull_and_mount_projection_chirho(&missing_config_chirho, 1).unwrap();
    let mounted_view_path_chirho =
        mounted_projection_path_chirho(&missing_fixture_chirho.replica_root_chirho)
            .parent()
            .unwrap()
            .join("views-chirho")
            .join(&mounted_receipt_chirho.view_digest_hex_chirho);
    std::fs::remove_file(mounted_view_path_chirho).unwrap();
    missing_fixture_chirho.publish_chirho(2, 101, 90, 'd');
    let missing_error_chirho =
        pull_and_mount_projection_chirho(&missing_config_chirho, 2).unwrap_err();
    assert!(missing_error_chirho
        .to_string()
        .contains("ProjectionReplicaMountedViewMissingChirho"));
    assert!(!missing_error_chirho
        .to_string()
        .contains("ProjectionReplicaViewFetchRefusedChirho"));
}

#[test]
fn transport_coordinates_refuse_public_or_credential_bearing_addresses_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho("private-transport");
    let mut source_config_chirho = fixture_chirho.source_config_chirho();
    source_config_chirho.listen_addr_chirho = "203.0.113.7:8408".to_owned();
    let public_bind_chirho = validate_source_config_chirho(&source_config_chirho).unwrap_err();
    assert!(public_bind_chirho
        .to_string()
        .contains("ProjectionReplicaPublicBindRefusedChirho"));
    assert!(!public_bind_chirho
        .to_string()
        .contains("ProjectionReplicaListenAddressRefusedChirho"));

    let mut pull_config_chirho = fixture_chirho.pull_config_chirho("http://203.0.113.7:8408");
    let public_source_chirho = validate_pull_config_chirho(&pull_config_chirho).unwrap_err();
    assert!(public_source_chirho
        .to_string()
        .contains("ProjectionReplicaSourceAddressRefusedChirho"));
    assert!(!public_source_chirho
        .to_string()
        .contains("ProjectionReplicaSourceUrlRefusedChirho"));

    pull_config_chirho.source_url_chirho =
        "http://operator-chirho:secret-chirho@10.100.0.7:8408".to_owned();
    let embedded_credential_chirho = validate_pull_config_chirho(&pull_config_chirho).unwrap_err();
    assert!(embedded_credential_chirho
        .to_string()
        .contains("ProjectionReplicaSourceUrlRefusedChirho"));
    assert!(!embedded_credential_chirho
        .to_string()
        .contains("ProjectionReplicaSourceAddressRefusedChirho"));
}
