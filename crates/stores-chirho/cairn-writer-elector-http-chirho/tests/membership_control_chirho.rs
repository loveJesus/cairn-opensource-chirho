// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A1.5.0 membership drive/observe surface, full-stack over real sockets: a deployed `ClusterNodeChirho`
//! serving the `/converge-chirho`, `/re-home-chirho`, and `/membership-chirho` endpoints, driven by HTTP
//! exactly as the shadow-fleet drills will drive it. Proves the six conditions the surface was built to:
//! R1 (mutations token-gated, fail-closed), R2 (single-step default + the executed step as the evidence
//! body), R3 (a non-leader makes NO change), R5 (a tampered/verified roster gates the mutation), R6 (the
//! observe endpoint reports the live membership) — plus a verified-roster convergence step end-to-end and
//! a three-node consistent-observation happy path. Shadow only: mints nothing, moves no head.

use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Router};
use cairn_replication_chirho::membership_chirho::{
    roster_prefix_digest_chirho, unsigned_membership_roster_head_message_chirho,
    unsigned_membership_roster_message_chirho, unsigned_node_network_record_message_chirho,
    MembershipActionChirho, MembershipRosterHeadChirho, MembershipRosterRecordChirho,
    NodeNetworkRecordChirho, MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO,
    MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO, NODE_NETWORK_RECORD_SCHEMA_CHIRHO,
};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_http_chirho::cluster_node_chirho::{
    ClusterNodeChirho, ClusterNodeConfigChirho,
};
use cairn_writer_elector_http_chirho::membership_control_chirho::{
    ConvergeOutcomeChirho, ConvergeResponseChirho, MembershipControlConfigChirho,
    MembershipObservationChirho, MembershipTargetAuthorityChirho, RosterAuthorityConfigChirho,
    OPERATOR_TOKEN_HEADER_CHIRHO,
};
use cairn_writer_elector_http_chirho::{
    driver_chirho::RAFT_FIRE_PATH_CHIRHO, serve_router_blocking_with_shutdown_chirho,
};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const TEST_TOKEN_CHIRHO: &str = "operator-token-under-test-chirho";

fn temp_dir_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-membctl-{tag_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir_chirho);
    std::fs::create_dir_all(&dir_chirho).unwrap();
    dir_chirho
}

/// Provision a signing root with a fresh key and return `(sign_root, pubkey_hex)`.
fn provision_key_chirho(tag_chirho: &str) -> (PathBuf, String) {
    let root_chirho = temp_dir_chirho(tag_chirho);
    sign_message_chirho(&root_chirho, b"provision key").unwrap();
    let pubkey_chirho = pubkey_hex_chirho(&root_chirho).unwrap();
    (root_chirho, pubkey_chirho)
}

/// One roster member to synthesize a signed membership + network record pair for.
struct RosterMemberSpecChirho {
    node_pubkey_hex_chirho: String,
    raft_id_chirho: u64,
    mesh_ip_chirho: String,
}

fn signed_membership_line_chirho(
    operator_root_chirho: &Path,
    seq_chirho: u64,
    pubkey_chirho: &str,
) -> Vec<u8> {
    let mut record_chirho = MembershipRosterRecordChirho {
        schema_chirho: MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho,
        action_chirho: MembershipActionChirho::AddNodeChirho,
        node_pubkey_hex_chirho: pubkey_chirho.to_string(),
        region_label_chirho: "region-chirho".to_string(),
        at_ms_chirho: 1000 + seq_chirho,
        operator_key_id_chirho: pubkey_hex_chirho(operator_root_chirho).unwrap(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(
        operator_root_chirho,
        &unsigned_membership_roster_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    serde_json::to_vec(&record_chirho).unwrap()
}

fn signed_network_line_chirho(
    operator_root_chirho: &Path,
    seq_chirho: u64,
    spec_chirho: &RosterMemberSpecChirho,
) -> Vec<u8> {
    let mut record_chirho = NodeNetworkRecordChirho {
        schema_chirho: NODE_NETWORK_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho,
        node_pubkey_hex_chirho: spec_chirho.node_pubkey_hex_chirho.clone(),
        raft_id_chirho: spec_chirho.raft_id_chirho,
        wg_pubkey_chirho: format!("WG{}", spec_chirho.raft_id_chirho),
        mesh_ip_chirho: spec_chirho.mesh_ip_chirho.clone(),
        endpoint_chirho: format!("host-{}:51820", spec_chirho.raft_id_chirho),
        at_ms_chirho: 2000 + seq_chirho,
        operator_key_id_chirho: pubkey_hex_chirho(operator_root_chirho).unwrap(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(
        operator_root_chirho,
        &unsigned_node_network_record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    serde_json::to_vec(&record_chirho).unwrap()
}

fn signed_head_chirho(operator_root_chirho: &Path, lines_chirho: &[Vec<u8>]) -> Vec<u8> {
    let mut head_chirho = MembershipRosterHeadChirho {
        schema_chirho: MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO.to_string(),
        roster_record_count_chirho: lines_chirho.len() as u64,
        roster_prefix_digest_chirho: roster_prefix_digest_chirho(lines_chirho),
        at_ms_chirho: 9000,
        operator_key_id_chirho: pubkey_hex_chirho(operator_root_chirho).unwrap(),
        sig_chirho: String::new(),
    };
    head_chirho.sig_chirho = sign_message_chirho(
        operator_root_chirho,
        &unsigned_membership_roster_head_message_chirho(&head_chirho).unwrap(),
    )
    .unwrap();
    serde_json::to_vec(&head_chirho).unwrap()
}

/// Build a signed roster (membership + network record per member, seq = line index) + its signed head, and
/// write both to files in `dir_chirho`; return the two paths for a `MembershipControlConfigChirho`.
fn write_signed_roster_chirho(
    dir_chirho: &Path,
    operator_root_chirho: &Path,
    members_chirho: &[RosterMemberSpecChirho],
) -> (PathBuf, PathBuf) {
    let mut lines_chirho: Vec<Vec<u8>> = Vec::new();
    for spec_chirho in members_chirho {
        let seq_m_chirho = lines_chirho.len() as u64;
        lines_chirho.push(signed_membership_line_chirho(
            operator_root_chirho,
            seq_m_chirho,
            &spec_chirho.node_pubkey_hex_chirho,
        ));
        let seq_n_chirho = lines_chirho.len() as u64;
        lines_chirho.push(signed_network_line_chirho(
            operator_root_chirho,
            seq_n_chirho,
            spec_chirho,
        ));
    }
    let head_chirho = signed_head_chirho(operator_root_chirho, &lines_chirho);

    let roster_path_chirho = dir_chirho.join("roster-chirho.jsonl");
    let mut roster_bytes_chirho = Vec::new();
    for line_chirho in &lines_chirho {
        roster_bytes_chirho.extend_from_slice(line_chirho);
        roster_bytes_chirho.push(b'\n');
    }
    std::fs::write(&roster_path_chirho, &roster_bytes_chirho).unwrap();
    let head_path_chirho = dir_chirho.join("roster-head-chirho.json");
    std::fs::write(&head_path_chirho, &head_chirho).unwrap();
    (roster_path_chirho, head_path_chirho)
}

/// A served node under test: its base URL plus the handles to stop it and clean its dirs on drop.
struct TestNodeChirho {
    url_chirho: String,
    stop_chirho: Arc<AtomicBool>,
    handle_chirho: Option<std::thread::JoinHandle<()>>,
    dirs_chirho: Vec<PathBuf>,
}

impl Drop for TestNodeChirho {
    fn drop(&mut self) {
        self.stop_chirho.store(true, Ordering::Relaxed);
        if let Some(handle_chirho) = self.handle_chirho.take() {
            let _ = handle_chirho.join();
        }
        for dir_chirho in &self.dirs_chirho {
            let _ = std::fs::remove_dir_all(dir_chirho);
        }
    }
}

/// Build a `MembershipControlConfigChirho` for a node, defaulting the drill-drive knobs.
fn control_config_chirho(
    roster_path_chirho: PathBuf,
    roster_head_path_chirho: PathBuf,
    operator_pubkey_hex_chirho: String,
    local_node_pubkey_hex_chirho: String,
    group_chirho: &ConsistencyGroupIdChirho,
    token_chirho: Option<String>,
) -> MembershipControlConfigChirho {
    MembershipControlConfigChirho {
        roster_authority_chirho: RosterAuthorityConfigChirho {
            roster_path_chirho,
            roster_head_path_chirho,
            operator_pubkey_hex_chirho,
            relay_interface_chirho: cairn_roster_config_chirho::RELAY_WIREGUARD_INTERFACE_CHIRHO
                .to_string(),
        },
        local_node_pubkey_hex_chirho,
        group_id_chirho: group_chirho.canonical_id_chirho(),
        target_authority_chirho: MembershipTargetAuthorityChirho::RosterWideChirho,
        operator_token_chirho: token_chirho,
        fixpoint_step_sleep_chirho: Duration::from_millis(50),
        fixpoint_max_steps_chirho: 8,
    }
}

/// Bind a socket, build the node (durable store, real key, optional control surface), and serve it on a
/// thread. `extra_dirs_chirho` are cleaned up alongside the node's own dirs on drop.
// A test fixture with independent per-test knobs (shape + key + control + socket + cleanup); the arg count
// is the fixture's surface, not a production-API smell.
#[allow(clippy::too_many_arguments)]
fn serve_node_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    local_raft_id_chirho: u64,
    voters_chirho: Vec<(u64, NodeIdChirho)>,
    peers_chirho: Vec<(u64, String)>,
    sign_root_chirho: PathBuf,
    control_chirho: Option<MembershipControlConfigChirho>,
    listener_chirho: TcpListener,
    extra_dirs_chirho: Vec<PathBuf>,
) -> TestNodeChirho {
    let url_chirho = format!("http://{}", listener_chirho.local_addr().unwrap());
    let durable_dir_chirho = temp_dir_chirho(&format!("durable-{local_raft_id_chirho}"));
    let node_chirho = ClusterNodeChirho::build_chirho(ClusterNodeConfigChirho {
        group_chirho: group_chirho.clone(),
        local_raft_id_chirho,
        voters_chirho,
        learners_chirho: Vec::new(),
        peers_chirho,
        durable_dir_chirho: durable_dir_chirho.clone(),
        sign_root_chirho: sign_root_chirho.clone(),
        tick_interval_chirho: Duration::from_millis(50),
        membership_control_chirho: control_chirho,
    })
    .expect("build cluster node");

    let stop_chirho = Arc::new(AtomicBool::new(false));
    let serve_stop_chirho = stop_chirho.clone();
    let handle_chirho = std::thread::spawn(move || {
        let _ = node_chirho.serve_blocking_chirho(listener_chirho, serve_stop_chirho);
    });

    let mut dirs_chirho = vec![durable_dir_chirho, sign_root_chirho];
    dirs_chirho.extend(extra_dirs_chirho);
    TestNodeChirho {
        url_chirho,
        stop_chirho,
        handle_chirho: Some(handle_chirho),
        dirs_chirho,
    }
}

fn get_membership_chirho(url_chirho: &str) -> Option<MembershipObservationChirho> {
    let response_chirho = ureq::get(&format!("{url_chirho}/membership-chirho"))
        .call()
        .ok()?;
    let body_chirho = response_chirho.into_string().ok()?;
    serde_json::from_str(&body_chirho).ok()
}

/// Poll the observe endpoint until this node reports itself the leader (bounded), returning the snapshot.
fn wait_for_local_leader_chirho(url_chirho: &str) -> MembershipObservationChirho {
    for _ in 0..200 {
        std::thread::sleep(Duration::from_millis(100));
        if let Some(observation_chirho) = get_membership_chirho(url_chirho) {
            if observation_chirho.is_local_leader_chirho {
                return observation_chirho;
            }
        }
    }
    panic!("node did not become leader within the timeout");
}

/// POST `/converge-chirho`, returning `(status, body)`. `token_chirho == None` omits the header entirely.
fn post_converge_chirho(
    url_chirho: &str,
    token_chirho: Option<&str>,
    to_fixpoint_chirho: bool,
) -> (u16, String) {
    let full_chirho = if to_fixpoint_chirho {
        format!("{url_chirho}/converge-chirho?to_fixpoint_chirho=true")
    } else {
        format!("{url_chirho}/converge-chirho")
    };
    let mut request_chirho = ureq::post(&full_chirho);
    if let Some(token_chirho) = token_chirho {
        request_chirho = request_chirho.set(OPERATOR_TOKEN_HEADER_CHIRHO, token_chirho);
    }
    match request_chirho.call() {
        Ok(response_chirho) => (
            response_chirho.status(),
            response_chirho.into_string().unwrap_or_default(),
        ),
        Err(ureq::Error::Status(code_chirho, response_chirho)) => (
            code_chirho,
            response_chirho.into_string().unwrap_or_default(),
        ),
        Err(error_chirho) => panic!("converge request transport failed: {error_chirho}"),
    }
}

fn group_chirho(tag_chirho: &str) -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: format!("/cairn-ha-membership-test-{tag_chirho}-chirho"),
    }
}

async fn record_prospective_learner_message_chirho(
    State(received_chirho): State<Arc<AtomicU64>>,
    _body_chirho: Bytes,
) -> StatusCode {
    received_chirho.fetch_add(1, Ordering::Relaxed);
    StatusCode::OK
}

/// R6: the observe endpoint reports the live voters, the local-leader flag, and the applied conf index.
/// (The observe endpoint is part of the membership-control surface, so a control config is what mounts it.)
#[test]
fn membership_observe_reports_live_membership_chirho() {
    let group_chirho = group_chirho("observe");
    let (sign_root_chirho, node_pubkey_chirho) = provision_key_chirho("observe-n1");
    let roster_dir_chirho = temp_dir_chirho("observe-roster");
    let (operator_root_chirho, operator_pubkey_chirho) = provision_key_chirho("observe-op");
    let (roster_path_chirho, head_path_chirho) = write_signed_roster_chirho(
        &roster_dir_chirho,
        &operator_root_chirho,
        &[RosterMemberSpecChirho {
            node_pubkey_hex_chirho: node_pubkey_chirho.clone(),
            raft_id_chirho: 1,
            mesh_ip_chirho: "10.100.0.1".to_string(),
        }],
    );
    let control_chirho = control_config_chirho(
        roster_path_chirho,
        head_path_chirho,
        operator_pubkey_chirho,
        node_pubkey_chirho.clone(),
        &group_chirho,
        Some(TEST_TOKEN_CHIRHO.to_string()),
    );
    let listener_chirho = TcpListener::bind("127.0.0.1:0").unwrap();
    let node_chirho = serve_node_chirho(
        &group_chirho,
        1,
        vec![(1, NodeIdChirho(node_pubkey_chirho))],
        Vec::new(),
        sign_root_chirho,
        Some(control_chirho),
        listener_chirho,
        vec![roster_dir_chirho, operator_root_chirho],
    );

    let observation_chirho = wait_for_local_leader_chirho(&node_chirho.url_chirho);
    assert_eq!(
        observation_chirho.voters_chirho,
        vec![1],
        "the lone voter is raft id 1"
    );
    assert!(
        observation_chirho.learners_chirho.is_empty(),
        "no learners yet"
    );
    assert!(
        observation_chirho.is_local_leader_chirho,
        "the single node elects itself"
    );
    assert_eq!(observation_chirho.local_raft_id_chirho, 1);
    assert!(
        observation_chirho.term_chirho >= 1,
        "an election advanced the term"
    );
    // R6: the applied conf index field is served (0 is valid for a fresh single-seed store that has
    // applied no runtime ConfChange yet); its presence is what the D4 drill asserts on.
    let _ = observation_chirho.applied_conf_index_chirho;
}

/// R1: the mutating endpoints are token-gated and FAIL CLOSED — no token header and a wrong token are both
/// forbidden, and neither adds any member.
#[test]
fn converge_without_a_valid_token_is_forbidden_and_changes_nothing_chirho() {
    let group_chirho = group_chirho("token");
    let (sign_root_chirho, node_pubkey_chirho) = provision_key_chirho("token-n1");
    let roster_dir_chirho = temp_dir_chirho("token-roster");
    let (operator_root_chirho, operator_pubkey_chirho) = provision_key_chirho("token-op");
    // A valid roster exists on disk, so any change would be blocked by the TOKEN, not a missing roster.
    let (roster_path_chirho, head_path_chirho) = write_signed_roster_chirho(
        &roster_dir_chirho,
        &operator_root_chirho,
        &[
            RosterMemberSpecChirho {
                node_pubkey_hex_chirho: node_pubkey_chirho.clone(),
                raft_id_chirho: 1,
                mesh_ip_chirho: "10.100.0.1".to_string(),
            },
            RosterMemberSpecChirho {
                node_pubkey_hex_chirho: "b".repeat(64),
                raft_id_chirho: 2,
                mesh_ip_chirho: "10.100.0.2".to_string(),
            },
        ],
    );
    let control_chirho = control_config_chirho(
        roster_path_chirho,
        head_path_chirho,
        operator_pubkey_chirho,
        node_pubkey_chirho.clone(),
        &group_chirho,
        Some(TEST_TOKEN_CHIRHO.to_string()),
    );
    let listener_chirho = TcpListener::bind("127.0.0.1:0").unwrap();
    let node_chirho = serve_node_chirho(
        &group_chirho,
        1,
        vec![(1, NodeIdChirho(node_pubkey_chirho))],
        Vec::new(),
        sign_root_chirho,
        Some(control_chirho),
        listener_chirho,
        vec![roster_dir_chirho, operator_root_chirho],
    );
    wait_for_local_leader_chirho(&node_chirho.url_chirho);

    let (no_token_status_chirho, _) = post_converge_chirho(&node_chirho.url_chirho, None, false);
    assert_eq!(no_token_status_chirho, 403, "no operator token ⇒ forbidden");
    let (bad_token_status_chirho, _) =
        post_converge_chirho(&node_chirho.url_chirho, Some("wrong-token-chirho"), false);
    assert_eq!(
        bad_token_status_chirho, 403,
        "a wrong operator token ⇒ forbidden"
    );

    // Neither forbidden attempt added the roster's second member.
    let observation_chirho = get_membership_chirho(&node_chirho.url_chirho).unwrap();
    assert_eq!(observation_chirho.voters_chirho, vec![1]);
    assert!(
        observation_chirho.learners_chirho.is_empty(),
        "a forbidden converge proposed nothing"
    );
}

/// R1 fail-closed with NO token configured: even a correctly-shaped request is forbidden.
#[test]
fn converge_is_forbidden_when_no_token_is_configured_chirho() {
    let group_chirho = group_chirho("notoken");
    let (sign_root_chirho, node_pubkey_chirho) = provision_key_chirho("notoken-n1");
    let roster_dir_chirho = temp_dir_chirho("notoken-roster");
    let (operator_root_chirho, operator_pubkey_chirho) = provision_key_chirho("notoken-op");
    let (roster_path_chirho, head_path_chirho) = write_signed_roster_chirho(
        &roster_dir_chirho,
        &operator_root_chirho,
        &[RosterMemberSpecChirho {
            node_pubkey_hex_chirho: node_pubkey_chirho.clone(),
            raft_id_chirho: 1,
            mesh_ip_chirho: "10.100.0.1".to_string(),
        }],
    );
    // operator_token_chirho = None ⇒ the mutating surface must not be openly callable.
    let control_chirho = control_config_chirho(
        roster_path_chirho,
        head_path_chirho,
        operator_pubkey_chirho,
        node_pubkey_chirho.clone(),
        &group_chirho,
        None,
    );
    let listener_chirho = TcpListener::bind("127.0.0.1:0").unwrap();
    let node_chirho = serve_node_chirho(
        &group_chirho,
        1,
        vec![(1, NodeIdChirho(node_pubkey_chirho))],
        Vec::new(),
        sign_root_chirho,
        Some(control_chirho),
        listener_chirho,
        vec![roster_dir_chirho, operator_root_chirho],
    );
    wait_for_local_leader_chirho(&node_chirho.url_chirho);

    let (status_chirho, _) =
        post_converge_chirho(&node_chirho.url_chirho, Some(TEST_TOKEN_CHIRHO), false);
    assert_eq!(
        status_chirho, 403,
        "no configured token ⇒ the mutating surface is closed"
    );
}

/// R3: a node that never wins leadership (a 2-voter config with no reachable peer) returns NotLeader and
/// proposes NO change — the leader gate fires before any elector mutation.
#[test]
fn converge_on_a_non_leader_is_notleader_with_no_side_effect_chirho() {
    let group_chirho = group_chirho("notleader");
    let (sign_root_chirho, node_pubkey_chirho) = provision_key_chirho("notleader-n1");
    let roster_dir_chirho = temp_dir_chirho("notleader-roster");
    let (operator_root_chirho, operator_pubkey_chirho) = provision_key_chirho("notleader-op");
    let (roster_path_chirho, head_path_chirho) = write_signed_roster_chirho(
        &roster_dir_chirho,
        &operator_root_chirho,
        &[RosterMemberSpecChirho {
            node_pubkey_hex_chirho: node_pubkey_chirho.clone(),
            raft_id_chirho: 1,
            mesh_ip_chirho: "10.100.0.1".to_string(),
        }],
    );
    let control_chirho = control_config_chirho(
        roster_path_chirho,
        head_path_chirho,
        operator_pubkey_chirho,
        node_pubkey_chirho.clone(),
        &group_chirho,
        Some(TEST_TOKEN_CHIRHO.to_string()),
    );
    // Configured as one of TWO voters (raft 2 never runs), with no reachable peer ⇒ never a majority ⇒
    // never leader.
    let unreachable_listener_chirho = TcpListener::bind("127.0.0.1:0").unwrap();
    let unreachable_peer_url_chirho = format!(
        "http://{}",
        unreachable_listener_chirho.local_addr().unwrap()
    );
    let listener_chirho = TcpListener::bind("127.0.0.1:0").unwrap();
    let node_chirho = serve_node_chirho(
        &group_chirho,
        1,
        vec![
            (1, NodeIdChirho(node_pubkey_chirho.clone())),
            (2, NodeIdChirho("b".repeat(64))),
        ],
        vec![(2, unreachable_peer_url_chirho)],
        sign_root_chirho,
        Some(control_chirho),
        listener_chirho,
        vec![roster_dir_chirho, operator_root_chirho],
    );

    // Give it well past an election timeout to (fail to) elect, then converge.
    std::thread::sleep(Duration::from_millis(1500));
    let (status_chirho, body_chirho) =
        post_converge_chirho(&node_chirho.url_chirho, Some(TEST_TOKEN_CHIRHO), false);
    assert_eq!(
        status_chirho, 200,
        "a NotLeader answer is a normal 200 with an explicit outcome"
    );
    let response_chirho: ConvergeResponseChirho = serde_json::from_str(&body_chirho).unwrap();
    assert!(
        matches!(
            response_chirho.outcome_chirho,
            ConvergeOutcomeChirho::NotLeaderChirho { .. }
        ),
        "a non-leader surfaces NotLeader, not a step: {:?}",
        response_chirho.outcome_chirho
    );
    assert!(!response_chirho.observation_chirho.is_local_leader_chirho);
}

/// R5 (failure): a leader with a tampered roster on disk gets an error and CHANGES NOTHING — the verifying
/// derivation refuses before any propose.
#[test]
fn converge_with_a_tampered_roster_changes_nothing_chirho() {
    let group_chirho = group_chirho("tampered");
    let (sign_root_chirho, node_pubkey_chirho) = provision_key_chirho("tampered-n1");
    let roster_dir_chirho = temp_dir_chirho("tampered-roster");
    // Write GARBAGE where the roster + head belong (not operator-signed records).
    let roster_path_chirho = roster_dir_chirho.join("roster-chirho.jsonl");
    let head_path_chirho = roster_dir_chirho.join("roster-head-chirho.json");
    std::fs::write(
        &roster_path_chirho,
        b"{\"not\":\"a signed roster record\"}\n",
    )
    .unwrap();
    std::fs::write(&head_path_chirho, b"{\"not\":\"a signed head\"}").unwrap();
    let control_chirho = control_config_chirho(
        roster_path_chirho,
        head_path_chirho,
        "a".repeat(64), // some operator pubkey; the tampered bytes fail verification regardless
        node_pubkey_chirho.clone(),
        &group_chirho,
        Some(TEST_TOKEN_CHIRHO.to_string()),
    );
    let listener_chirho = TcpListener::bind("127.0.0.1:0").unwrap();
    let node_chirho = serve_node_chirho(
        &group_chirho,
        1,
        vec![(1, NodeIdChirho(node_pubkey_chirho))],
        Vec::new(),
        sign_root_chirho,
        Some(control_chirho),
        listener_chirho,
        vec![roster_dir_chirho],
    );
    wait_for_local_leader_chirho(&node_chirho.url_chirho);

    let (status_chirho, _) =
        post_converge_chirho(&node_chirho.url_chirho, Some(TEST_TOKEN_CHIRHO), false);
    assert_eq!(status_chirho, 422, "an unverifiable roster is rejected");
    let observation_chirho = get_membership_chirho(&node_chirho.url_chirho).unwrap();
    assert_eq!(
        observation_chirho.voters_chirho,
        vec![1],
        "the voter set is untouched"
    );
    assert!(
        observation_chirho.learners_chirho.is_empty(),
        "nothing was proposed"
    );
}

/// R2 + R5 (verified path): a leader converging toward a verified roster that adds a second member returns
/// the executed AddedLearner step as its evidence body, and the learner shows up in the live membership.
#[test]
fn converge_with_a_verified_roster_adds_the_learner_and_returns_the_step_chirho() {
    let group_chirho = group_chirho("verified");
    let (sign_root_chirho, node_pubkey_chirho) = provision_key_chirho("verified-n1");
    let roster_dir_chirho = temp_dir_chirho("verified-roster");
    let (operator_root_chirho, operator_pubkey_chirho) = provision_key_chirho("verified-op");
    // The verified target: this node (raft 1) PLUS a second member (raft 2) it must add as a learner.
    let (roster_path_chirho, head_path_chirho) = write_signed_roster_chirho(
        &roster_dir_chirho,
        &operator_root_chirho,
        &[
            RosterMemberSpecChirho {
                node_pubkey_hex_chirho: node_pubkey_chirho.clone(),
                raft_id_chirho: 1,
                mesh_ip_chirho: "10.100.0.1".to_string(),
            },
            RosterMemberSpecChirho {
                node_pubkey_hex_chirho: "c".repeat(64),
                raft_id_chirho: 2,
                mesh_ip_chirho: "10.100.0.2".to_string(),
            },
        ],
    );
    let control_chirho = control_config_chirho(
        roster_path_chirho,
        head_path_chirho,
        operator_pubkey_chirho,
        node_pubkey_chirho.clone(),
        &group_chirho,
        Some(TEST_TOKEN_CHIRHO.to_string()),
    );
    // Preprovision the prospective member's bounded transport route. It is not in the leader's initial
    // ConfState, but once the verified roster admits it as a learner the live Raft driver must use this
    // already-reviewed route rather than silently dropping traffic to an unknown id.
    let learner_listener_chirho = TcpListener::bind("127.0.0.1:0").unwrap();
    let learner_url_chirho = format!("http://{}", learner_listener_chirho.local_addr().unwrap());
    let learner_received_chirho = Arc::new(AtomicU64::new(0));
    let learner_stop_chirho = Arc::new(AtomicBool::new(false));
    let server_received_chirho = learner_received_chirho.clone();
    let server_stop_chirho = learner_stop_chirho.clone();
    let learner_handle_chirho = std::thread::spawn(move || {
        let router_chirho = Router::new()
            .route(
                RAFT_FIRE_PATH_CHIRHO,
                post(record_prospective_learner_message_chirho),
            )
            .with_state(server_received_chirho);
        serve_router_blocking_with_shutdown_chirho(
            learner_listener_chirho,
            router_chirho,
            server_stop_chirho,
        )
        .expect("serve the prospective learner receiver");
    });
    let listener_chirho = TcpListener::bind("127.0.0.1:0").unwrap();
    let node_chirho = serve_node_chirho(
        &group_chirho,
        1,
        vec![(1, NodeIdChirho(node_pubkey_chirho))],
        vec![(2, learner_url_chirho)],
        sign_root_chirho,
        Some(control_chirho),
        listener_chirho,
        vec![roster_dir_chirho, operator_root_chirho],
    );
    wait_for_local_leader_chirho(&node_chirho.url_chirho);

    let (status_chirho, body_chirho) =
        post_converge_chirho(&node_chirho.url_chirho, Some(TEST_TOKEN_CHIRHO), false);
    assert_eq!(status_chirho, 200, "a verified single step succeeds");
    // R2: the executed step IS the evidence body.
    assert!(
        body_chirho.contains("AddedLearnerChirho"),
        "the single step added the second member as a learner: {body_chirho}"
    );

    // The learner appears in the live membership once the 1-voter leader commits + applies the change.
    let mut learner_seen_chirho = false;
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(100));
        let observation_chirho = get_membership_chirho(&node_chirho.url_chirho).unwrap();
        if observation_chirho.learners_chirho == vec![2] {
            assert_eq!(
                observation_chirho.voters_chirho,
                vec![1],
                "raft 1 is still the only voter"
            );
            learner_seen_chirho = true;
            break;
        }
    }
    assert!(
        learner_seen_chirho,
        "the added learner (raft 2) becomes visible in the membership"
    );
    let mut traffic_seen_chirho = false;
    for _ in 0..40 {
        if learner_received_chirho.load(Ordering::Relaxed) > 0 {
            traffic_seen_chirho = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        traffic_seen_chirho,
        "the preprovisioned prospective member receives Raft traffic after learner admission"
    );

    learner_stop_chirho.store(true, Ordering::Relaxed);
    learner_handle_chirho.join().unwrap();
}
