// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use axum::{http::StatusCode, routing::get, Json};
use cairn_write_relay_chirho::{
    CallerIdempotencyKeyChirho, PreparedServedWriteRelayAttemptChirho,
    PreparedServedWriteRelayRequestV1Chirho, RelayEndToEndHeadersChirho,
    RelayExecutionKnowledgeChirho, RelayOutcomeClassChirho, RelayRefusalIdentityChirho,
    RelayRosterChirho, ServedWriteDispatchInputChirho, ServedWriteDispatchOutcomeChirho,
    ServedWriteDispatchPortChirho, ServedWriteRelayPortChirho, ServedWriteRelayRequestInputChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::{LeadershipChirho, NodeIdChirho};
use cairn_writer_elector_chirho::monotonic_clock_chirho::FakeMonotonicClockChirho;
use cairn_writer_elector_http_chirho::{
    LeaderInfoChirho, LeaseTierChirho, LEADER_DISCOVERY_PATH_CHIRHO,
};
use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct StaticWriterElectorChirho {
    leadership_chirho: RwLock<LeadershipChirho>,
}

impl StaticWriterElectorChirho {
    fn new_chirho(leadership_chirho: LeadershipChirho) -> Arc<Self> {
        Arc::new(Self {
            leadership_chirho: RwLock::new(leadership_chirho),
        })
    }

    fn set_leadership_chirho(&self, leadership_chirho: LeadershipChirho) {
        *self
            .leadership_chirho
            .write()
            .expect("static elector write lock") = leadership_chirho;
    }
}

impl FixedGroupLeadershipViewChirho for StaticWriterElectorChirho {
    fn current_leadership_chirho(&self) -> LeadershipChirho {
        self.leadership_chirho
            .read()
            .expect("static elector read lock")
            .clone()
    }
}

struct RecordingExecutionChirho {
    calls_chirho: AtomicUsize,
    delay_chirho: Duration,
}

impl RecordingExecutionChirho {
    fn new_chirho(delay_chirho: Duration) -> Arc<Self> {
        Arc::new(Self {
            calls_chirho: AtomicUsize::new(0),
            delay_chirho,
        })
    }

    fn calls_chirho(&self) -> usize {
        self.calls_chirho.load(Ordering::Acquire)
    }
}

impl RelayDestinationExecutionPortChirho for RecordingExecutionChirho {
    fn execute_verified_chirho<'a>(
        &'a self,
        _request_chirho: &'a cairn_write_relay_chirho::VerifiedServedWriteRelayRequestChirho,
    ) -> RelayDestinationExecutionFutureChirho<'a> {
        Box::pin(async move {
            self.calls_chirho.fetch_add(1, Ordering::AcqRel);
            if !self.delay_chirho.is_zero() {
                tokio::time::sleep(self.delay_chirho).await;
            }
            RelayDestinationResponseChirho::served_chirho(
                202,
                RelayEndToEndHeadersChirho::try_response_chirho(vec![(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )])
                .expect("response headers"),
                br#"{"accepted_chirho":true}"#.to_vec(),
            )
        })
    }
}

struct ChildProcessExecutionChirho {
    marker_path_chirho: PathBuf,
}

impl RelayDestinationExecutionPortChirho for ChildProcessExecutionChirho {
    fn execute_verified_chirho<'a>(
        &'a self,
        _request_chirho: &'a cairn_write_relay_chirho::VerifiedServedWriteRelayRequestChirho,
    ) -> RelayDestinationExecutionFutureChirho<'a> {
        Box::pin(async move {
            std::fs::write(&self.marker_path_chirho, b"executed-chirho")
                .expect("write child execution marker");
            RelayDestinationResponseChirho::served_chirho(
                200,
                RelayEndToEndHeadersChirho::try_response_chirho(vec![(
                    "content-type".to_string(),
                    "text/plain".to_string(),
                )])
                .expect("child response headers"),
                b"two-process-response-chirho".to_vec(),
            )
        })
    }
}

struct InvalidSignatureSignerChirho {
    node_id_chirho: String,
}

impl RelayResponseSignerChirho for InvalidSignatureSignerChirho {
    fn sign_digest_chirho(&self, _digest_chirho: &[u8; 32]) -> anyhow::Result<(String, String)> {
        Ok((self.node_id_chirho.clone(), "00".repeat(64)))
    }
}

struct RelayFixtureChirho {
    _origin_root_chirho: TempDir,
    _target_root_chirho: TempDir,
    origin_path_chirho: PathBuf,
    target_path_chirho: PathBuf,
    origin_id_chirho: String,
    target_id_chirho: String,
    group_digest_chirho: String,
    roster_chirho: Arc<RelayRosterChirho>,
    follower_elector_chirho: Arc<StaticWriterElectorChirho>,
    destination_elector_chirho: Arc<StaticWriterElectorChirho>,
    follower_clock_chirho: Arc<FakeMonotonicClockChirho>,
    destination_clock_chirho: Arc<FakeMonotonicClockChirho>,
}

impl RelayFixtureChirho {
    fn new_chirho() -> Self {
        let origin_root_chirho = tempfile::tempdir().expect("origin root");
        let target_root_chirho = tempfile::tempdir().expect("target root");
        let origin_path_chirho = origin_root_chirho.path().to_path_buf();
        let target_path_chirho = target_root_chirho.path().to_path_buf();
        let origin_id_chirho = provision_node_chirho(&origin_path_chirho);
        let target_id_chirho = provision_node_chirho(&target_path_chirho);
        let group_digest_chirho = blake3::hash(b"relay-test-tenant-chirho")
            .to_hex()
            .to_string();
        let roster_chirho = Arc::new(
            RelayRosterChirho::new_chirho([origin_id_chirho.clone(), target_id_chirho.clone()])
                .expect("relay roster"),
        );
        let follower_elector_chirho =
            StaticWriterElectorChirho::new_chirho(follower_view_chirho(&target_id_chirho, 7));
        let destination_elector_chirho =
            StaticWriterElectorChirho::new_chirho(leader_view_chirho(&target_id_chirho, 7, true));
        Self {
            _origin_root_chirho: origin_root_chirho,
            _target_root_chirho: target_root_chirho,
            origin_path_chirho,
            target_path_chirho,
            origin_id_chirho,
            target_id_chirho,
            group_digest_chirho,
            roster_chirho,
            follower_elector_chirho,
            destination_elector_chirho,
            follower_clock_chirho: FakeMonotonicClockChirho::new_chirho(),
            destination_clock_chirho: FakeMonotonicClockChirho::new_chirho(),
        }
    }

    fn signed_request_chirho(
        &self,
        group_digest_chirho: &str,
        target_node_id_chirho: &str,
        term_chirho: u64,
        budget_millis_chirho: u64,
        origin_path_chirho: &Path,
        origin_node_id_chirho: &str,
    ) -> cairn_write_relay_chirho::ServedWriteRelayRequestV1Chirho {
        let prepared_chirho = PreparedServedWriteRelayRequestV1Chirho::new_chirho(
            ServedWriteRelayRequestInputChirho {
                ingress_admission_chirho: None,
                origin_node_id_chirho: origin_node_id_chirho.to_string(),
                target_node_id_chirho: target_node_id_chirho.to_string(),
                consistency_group_digest_chirho: group_digest_chirho.to_string(),
                expected_term_chirho: term_chirho,
                caller_idempotency_key_chirho: CallerIdempotencyKeyChirho::new_chirho(
                    "relay-fixture-operation-0001-chirho",
                )
                .expect("caller key"),
                method_chirho: "POST".to_string(),
                uri_chirho: "/app-chirho/demo-chirho/spend-chirho".to_string(),
                end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_request_chirho(vec![
                    (
                        "authorization".to_string(),
                        "Bearer private-relay-token-chirho".to_string(),
                    ),
                    ("content-type".to_string(), "application/json".to_string()),
                ])
                .expect("request headers"),
                body_chirho: br#"{"private_body_chirho":"needle-chirho"}"#.to_vec(),
                relay_budget_remaining_millis_chirho: budget_millis_chirho,
            },
        )
        .expect("prepared request");
        let possession_chirho =
            cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho(
                origin_path_chirho,
                &prepared_chirho.signing_digest_chirho(),
            )
            .expect("sign relay request");
        assert_eq!(possession_chirho.key_id_chirho(), origin_node_id_chirho);
        prepared_chirho
            .into_signed_chirho(possession_chirho.into_signature_hex_chirho())
            .expect("signed request")
    }

    fn attempt_chirho(&self, budget_millis_chirho: u64) -> PreparedServedWriteRelayAttemptChirho {
        PreparedServedWriteRelayAttemptChirho::new_chirho(
            self.signed_request_chirho(
                &self.group_digest_chirho,
                &self.target_id_chirho,
                7,
                budget_millis_chirho,
                &self.origin_path_chirho,
                &self.origin_id_chirho,
            ),
            &self.group_digest_chirho,
            &self.target_id_chirho,
            &self.roster_chirho,
        )
        .expect("prepared relay attempt")
    }

    fn spawn_server_chirho(
        &self,
        leader_info_chirho: LeaderInfoChirho,
        execution_chirho: Arc<RecordingExecutionChirho>,
        signer_chirho: Arc<dyn RelayResponseSignerChirho>,
    ) -> String {
        let state_chirho = RelayServerStateChirho::new_chirho(RelayServerConfigChirho {
            group_digest_chirho: self.group_digest_chirho.clone(),
            node_id_chirho: self.target_id_chirho.clone(),
            roster_chirho: Arc::clone(&self.roster_chirho),
            leadership_chirho: self.destination_elector_chirho.clone(),
            clock_chirho: self.destination_clock_chirho.clone(),
            transit_budget_millis_chirho: NonZeroU64::new(10).expect("nonzero transit"),
            signer_chirho,
            execution_chirho,
        })
        .expect("relay server state");
        let router_chirho = relay_router_chirho(state_chirho).route(
            LEADER_DISCOVERY_PATH_CHIRHO,
            get(move || {
                let leader_info_chirho = leader_info_chirho.clone();
                async move { Json(leader_info_chirho) }
            }),
        );
        let listener_chirho =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind relay fixture");
        let address_chirho = listener_chirho.local_addr().expect("relay fixture address");
        std::thread::spawn(move || {
            serve_relay_router_blocking_chirho(listener_chirho, router_chirho)
                .expect("serve relay fixture");
        });
        format!("http://{address_chirho}")
    }

    fn port_chirho(
        &self,
        endpoint_chirho: String,
        timeouts_chirho: RelayHttpTimeoutsChirho,
        transit_budget_millis_chirho: u64,
    ) -> HttpServedWriteRelayPortChirho {
        let directory_chirho = FixedRelayDirectoryChirho::new_for_test_chirho(
            self.group_digest_chirho.clone(),
            self.follower_elector_chirho.clone(),
            BTreeMap::from([(self.target_id_chirho.clone(), endpoint_chirho)]),
            &self.roster_chirho,
            self.follower_clock_chirho.clone(),
            NonZeroU64::new(transit_budget_millis_chirho).expect("nonzero transit"),
        )
        .expect("fixed relay directory");
        HttpServedWriteRelayPortChirho::new_chirho(
            Arc::new(directory_chirho),
            Arc::clone(&self.roster_chirho),
            timeouts_chirho,
        )
    }

    fn existing_signer_chirho(&self) -> Arc<dyn RelayResponseSignerChirho> {
        Arc::new(
            ExistingKeyRelayResponseSignerChirho::new_chirho(
                &self.target_path_chirho,
                self.target_id_chirho.clone(),
            )
            .expect("existing-key response signer"),
        )
    }
}

fn provision_node_chirho(root_chirho: &Path) -> String {
    cairn_signer_chirho::signer_chirho::sign_message_chirho(root_chirho, b"seed-node-chirho")
        .expect("provision node key");
    cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho(root_chirho)
        .expect("read node id")
}

fn follower_view_chirho(target_id_chirho: &str, term_chirho: u64) -> LeadershipChirho {
    LeadershipChirho {
        is_leader_chirho: false,
        leader_id_chirho: Some(NodeIdChirho(target_id_chirho.to_string())),
        term_chirho,
        lease_valid_chirho: false,
    }
}

fn leader_view_chirho(
    target_id_chirho: &str,
    term_chirho: u64,
    lease_valid_chirho: bool,
) -> LeadershipChirho {
    LeadershipChirho {
        is_leader_chirho: true,
        leader_id_chirho: Some(NodeIdChirho(target_id_chirho.to_string())),
        term_chirho,
        lease_valid_chirho,
    }
}

fn leader_info_chirho(
    target_id_chirho: &str,
    term_chirho: u64,
    remaining_millis_chirho: Option<u64>,
    tier_chirho: LeaseTierChirho,
) -> LeaderInfoChirho {
    LeaderInfoChirho {
        leader_node_id_chirho: Some(target_id_chirho.to_string()),
        is_local_leader_chirho: true,
        term_chirho,
        lease_remaining_millis_chirho: remaining_millis_chirho,
        lease_tier_chirho: tier_chirho,
    }
}

fn run_relay_chirho(
    port_chirho: &HttpServedWriteRelayPortChirho,
    attempt_chirho: &PreparedServedWriteRelayAttemptChirho,
) -> Result<Vec<u8>, cairn_write_relay_chirho::ServedWriteRelayFailureChirho> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("relay test runtime")
        .block_on(port_chirho.relay_one_hop_chirho(attempt_chirho))
}

#[test]
fn two_node_socket_relay_returns_exact_authenticated_response_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let execution_chirho = RecordingExecutionChirho::new_chirho(Duration::ZERO);
    let endpoint_chirho = fixture_chirho.spawn_server_chirho(
        leader_info_chirho(
            &fixture_chirho.target_id_chirho,
            7,
            Some(2_000),
            LeaseTierChirho::MonotonicDecayChirho,
        ),
        Arc::clone(&execution_chirho),
        fixture_chirho.existing_signer_chirho(),
    );
    let port_chirho =
        fixture_chirho.port_chirho(endpoint_chirho, RelayHttpTimeoutsChirho::default(), 25);
    let attempt_chirho = fixture_chirho.attempt_chirho(2_000);
    let wire_chirho = run_relay_chirho(&port_chirho, &attempt_chirho).expect("relay success");
    let verified_chirho = attempt_chirho
        .verify_response_chirho(&wire_chirho, &fixture_chirho.roster_chirho)
        .expect("verified response");
    assert_eq!(verified_chirho.actual_term_chirho(), 7);
    assert_eq!(
        verified_chirho.outcome_class_chirho(),
        RelayOutcomeClassChirho::ServedResponseChirho
    );
    assert_eq!(verified_chirho.status_chirho(), 202);
    assert_eq!(
        verified_chirho.body_chirho(),
        br#"{"accepted_chirho":true}"#
    );
    assert_eq!(execution_chirho.calls_chirho(), 1);
}

#[test]
fn two_node_dispatch_signs_relays_verifies_and_executes_exactly_once_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let execution_chirho = RecordingExecutionChirho::new_chirho(Duration::ZERO);
    let endpoint_chirho = fixture_chirho.spawn_server_chirho(
        leader_info_chirho(
            &fixture_chirho.target_id_chirho,
            7,
            Some(2_000),
            LeaseTierChirho::MonotonicDecayChirho,
        ),
        Arc::clone(&execution_chirho),
        fixture_chirho.existing_signer_chirho(),
    );
    let relay_chirho: Arc<dyn ServedWriteRelayPortChirho> = Arc::new(fixture_chirho.port_chirho(
        endpoint_chirho,
        RelayHttpTimeoutsChirho::default(),
        25,
    ));
    let signer_chirho = Arc::new(
        ExistingKeyRelayRequestSignerChirho::new_chirho(
            &fixture_chirho.origin_path_chirho,
            fixture_chirho.origin_id_chirho.clone(),
        )
        .expect("origin existing-key signer"),
    );
    let dispatcher_chirho = HttpServedWriteDispatchPortChirho::new_chirho(
        fixture_chirho.origin_id_chirho.clone(),
        fixture_chirho.group_digest_chirho.clone(),
        Arc::clone(&fixture_chirho.roster_chirho),
        fixture_chirho.follower_elector_chirho.clone(),
        signer_chirho,
        relay_chirho,
        LocalRelayDispatchPolicyChirho::new_chirho(
            NonZeroU64::new(2_000).expect("relay budget"),
            LocalRelayAuthorityReadinessChirho::new_chirho(),
        ),
    )
    .expect("two-node dispatcher");
    let outcome_chirho = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("dispatch runtime")
        .block_on(
            dispatcher_chirho.dispatch_chirho(ServedWriteDispatchInputChirho {
                ingress_admission_chirho: Some(
                    cairn_write_relay_chirho::RelayIngressAdmissionChirho::new_chirho(
                        60_000, 60, 8_388_608, 600, 67_108_864,
                    )
                    .expect("fixture ingress"),
                ),
                caller_idempotency_key_chirho: CallerIdempotencyKeyChirho::new_chirho(
                    "two-node-customer-operation-0001-chirho",
                )
                .expect("caller key"),
                method_chirho: "POST".to_string(),
                uri_chirho: "/app-chirho/credits-demo-chirho/spend-chirho".to_string(),
                end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_request_chirho(vec![
                    (
                        "authorization".to_string(),
                        "Bearer private-relay-token-chirho".to_string(),
                    ),
                    ("content-type".to_string(), "application/json".to_string()),
                ])
                .expect("request headers"),
                body_chirho: br#"{"amount_chirho":1}"#.to_vec(),
            }),
        )
        .expect("two-node dispatch");
    let ServedWriteDispatchOutcomeChirho::RelayedChirho(response_chirho) = outcome_chirho else {
        panic!("follower dispatch must return the owner's verified response");
    };
    assert_eq!(response_chirho.status_chirho(), 202);
    assert_eq!(
        response_chirho.body_chirho(),
        br#"{"accepted_chirho":true}"#
    );
    assert_eq!(
        execution_chirho.calls_chirho(),
        1,
        "the destination authority port must execute exactly once"
    );
}

#[test]
fn fixed_directory_refuses_dns_public_and_credentialed_endpoints_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    for endpoint_chirho in [
        "http://example.com:8080",
        "http://8.8.8.8:8080",
        "http://user:secret@127.0.0.1:8080",
    ] {
        let result_chirho = FixedRelayDirectoryChirho::new_for_test_chirho(
            fixture_chirho.group_digest_chirho.clone(),
            fixture_chirho.follower_elector_chirho.clone(),
            BTreeMap::from([(
                fixture_chirho.target_id_chirho.clone(),
                endpoint_chirho.to_string(),
            )]),
            &fixture_chirho.roster_chirho,
            fixture_chirho.follower_clock_chirho.clone(),
            NonZeroU64::new(25).expect("nonzero transit"),
        );
        assert!(
            result_chirho.is_err(),
            "ambient endpoint must not enter the fixed relay directory: {endpoint_chirho}"
        );
    }
}

#[test]
fn absent_or_consumed_remote_duration_refuses_before_execution_chirho() {
    for (remaining_chirho, tier_chirho) in [
        (None, LeaseTierChirho::TickWarmupChirho),
        (Some(20), LeaseTierChirho::MonotonicDecayChirho),
    ] {
        let fixture_chirho = RelayFixtureChirho::new_chirho();
        let execution_chirho = RecordingExecutionChirho::new_chirho(Duration::ZERO);
        let endpoint_chirho = fixture_chirho.spawn_server_chirho(
            leader_info_chirho(
                &fixture_chirho.target_id_chirho,
                7,
                remaining_chirho,
                tier_chirho,
            ),
            Arc::clone(&execution_chirho),
            fixture_chirho.existing_signer_chirho(),
        );
        let port_chirho =
            fixture_chirho.port_chirho(endpoint_chirho, RelayHttpTimeoutsChirho::default(), 25);
        let error_chirho = run_relay_chirho(&port_chirho, &fixture_chirho.attempt_chirho(2_000))
            .expect_err("absent or consumed duration must refuse");
        assert_eq!(
            error_chirho.identity_chirho(),
            RelayRefusalIdentityChirho::RelayLeaseExpiredChirho
        );
        assert_ne!(
            error_chirho.identity_chirho(),
            RelayRefusalIdentityChirho::RelayOwnerUnavailableChirho
        );
        assert_eq!(execution_chirho.calls_chirho(), 0);
    }
}

#[test]
fn unknown_and_unroutable_owners_keep_distinct_pre_execution_identities_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    fixture_chirho
        .follower_elector_chirho
        .set_leadership_chirho(LeadershipChirho {
            is_leader_chirho: false,
            leader_id_chirho: None,
            term_chirho: 7,
            lease_valid_chirho: false,
        });
    let unknown_port_chirho = fixture_chirho.port_chirho(
        "http://127.0.0.1:9".to_string(),
        RelayHttpTimeoutsChirho::default(),
        25,
    );
    let unknown_chirho =
        run_relay_chirho(&unknown_port_chirho, &fixture_chirho.attempt_chirho(2_000))
            .expect_err("missing owner must refuse");
    assert_eq!(
        unknown_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayOwnerUnknownChirho
    );

    fixture_chirho
        .follower_elector_chirho
        .set_leadership_chirho(follower_view_chirho(&fixture_chirho.target_id_chirho, 7));
    let directory_chirho = FixedRelayDirectoryChirho::new_for_test_chirho(
        fixture_chirho.group_digest_chirho.clone(),
        fixture_chirho.follower_elector_chirho.clone(),
        BTreeMap::from([(
            fixture_chirho.origin_id_chirho.clone(),
            "http://127.0.0.1:9".to_string(),
        )]),
        &fixture_chirho.roster_chirho,
        fixture_chirho.follower_clock_chirho.clone(),
        NonZeroU64::new(25).expect("nonzero transit"),
    )
    .expect("partial fixed directory");
    let unroutable_port_chirho = HttpServedWriteRelayPortChirho::new_chirho(
        Arc::new(directory_chirho),
        Arc::clone(&fixture_chirho.roster_chirho),
        RelayHttpTimeoutsChirho::default(),
    );
    let unroutable_chirho = run_relay_chirho(
        &unroutable_port_chirho,
        &fixture_chirho.attempt_chirho(2_000),
    )
    .expect_err("owner without endpoint must refuse");
    assert_eq!(
        unroutable_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayOwnerUnroutableChirho
    );
    assert_ne!(
        unroutable_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayOwnerUnknownChirho
    );
}

#[test]
fn authenticated_wrong_group_returns_an_exact_signed_pre_execution_refusal_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    fixture_chirho
        .destination_elector_chirho
        .set_leadership_chirho(leader_view_chirho(
            &fixture_chirho.target_id_chirho,
            11,
            true,
        ));
    let execution_chirho = RecordingExecutionChirho::new_chirho(Duration::ZERO);
    let endpoint_chirho = fixture_chirho.spawn_server_chirho(
        leader_info_chirho(
            &fixture_chirho.target_id_chirho,
            7,
            Some(2_000),
            LeaseTierChirho::MonotonicDecayChirho,
        ),
        Arc::clone(&execution_chirho),
        fixture_chirho.existing_signer_chirho(),
    );
    let wrong_group_chirho = blake3::hash(b"wrong-group-chirho").to_hex().to_string();
    let signed_request_chirho = fixture_chirho.signed_request_chirho(
        &wrong_group_chirho,
        &fixture_chirho.target_id_chirho,
        7,
        2_000,
        &fixture_chirho.origin_path_chirho,
        &fixture_chirho.origin_id_chirho,
    );
    let attempt_chirho = PreparedServedWriteRelayAttemptChirho::new_chirho(
        signed_request_chirho,
        &wrong_group_chirho,
        &fixture_chirho.target_id_chirho,
        &fixture_chirho.roster_chirho,
    )
    .expect("wrong-group request is internally authentic before destination binding");
    let directory_chirho = FixedRelayDirectoryChirho::new_for_test_chirho(
        wrong_group_chirho,
        fixture_chirho.follower_elector_chirho.clone(),
        BTreeMap::from([(fixture_chirho.target_id_chirho.clone(), endpoint_chirho)]),
        &fixture_chirho.roster_chirho,
        fixture_chirho.follower_clock_chirho.clone(),
        NonZeroU64::new(25).expect("nonzero transit"),
    )
    .expect("wrong-group follower directory");
    let port_chirho = HttpServedWriteRelayPortChirho::new_chirho(
        Arc::new(directory_chirho),
        Arc::clone(&fixture_chirho.roster_chirho),
        RelayHttpTimeoutsChirho::default(),
    );

    let response_wire_chirho =
        run_relay_chirho(&port_chirho, &attempt_chirho).expect("signed binding refusal");
    let verified_chirho = attempt_chirho
        .verify_response_chirho(&response_wire_chirho, &fixture_chirho.roster_chirho)
        .expect("the intended destination signs the exact wrong-group refusal");
    assert_eq!(
        verified_chirho.outcome_class_chirho(),
        RelayOutcomeClassChirho::RelayRefusalChirho
    );
    assert_eq!(
        verified_chirho.outcome_identity_chirho(),
        Some(RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho.as_str_chirho())
    );
    assert_ne!(
        verified_chirho.outcome_identity_chirho(),
        Some(RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho.as_str_chirho())
    );
    assert_eq!(
        verified_chirho.status_chirho(),
        StatusCode::CONFLICT.as_u16()
    );
    assert_eq!(
        verified_chirho.consistency_group_digest_chirho(),
        fixture_chirho.group_digest_chirho,
        "the signed refusal binds the responder's actual selected group"
    );
    assert_eq!(
        verified_chirho.actual_term_chirho(),
        11,
        "the signed refusal reports the responder's actual term rather than echoing the request"
    );
    assert_eq!(execution_chirho.calls_chirho(), 0);
}

#[test]
fn wrong_recipient_and_unrostered_origin_refuse_before_fake_execution_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let execution_chirho = RecordingExecutionChirho::new_chirho(Duration::ZERO);
    let endpoint_chirho = fixture_chirho.spawn_server_chirho(
        leader_info_chirho(
            &fixture_chirho.target_id_chirho,
            7,
            Some(2_000),
            LeaseTierChirho::MonotonicDecayChirho,
        ),
        Arc::clone(&execution_chirho),
        fixture_chirho.existing_signer_chirho(),
    );
    let third_root_chirho = tempfile::tempdir().expect("third root");
    let third_id_chirho = provision_node_chirho(third_root_chirho.path());
    let requests_chirho = [
        fixture_chirho.signed_request_chirho(
            &fixture_chirho.group_digest_chirho,
            &fixture_chirho.origin_id_chirho,
            7,
            2_000,
            &fixture_chirho.origin_path_chirho,
            &fixture_chirho.origin_id_chirho,
        ),
        fixture_chirho.signed_request_chirho(
            &fixture_chirho.group_digest_chirho,
            &fixture_chirho.target_id_chirho,
            7,
            2_000,
            third_root_chirho.path(),
            &third_id_chirho,
        ),
    ];
    let agent_chirho = ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .redirects(0)
        .build();
    for request_chirho in requests_chirho {
        let response_chirho = agent_chirho
            .post(&format!(
                "{endpoint_chirho}{SERVED_WRITE_RELAY_PATH_CHIRHO}"
            ))
            .send_bytes(&request_chirho.to_wire_bytes_chirho().expect("request wire"))
            .expect_err("invalid request must be an HTTP refusal");
        assert_eq!(response_chirho.kind(), ureq::ErrorKind::HTTP);
    }
    assert_eq!(execution_chirho.calls_chirho(), 0);
}

#[test]
fn destination_term_drift_returns_the_exact_signed_refusal_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    fixture_chirho
        .destination_elector_chirho
        .set_leadership_chirho(leader_view_chirho(
            &fixture_chirho.target_id_chirho,
            8,
            true,
        ));
    let execution_chirho = RecordingExecutionChirho::new_chirho(Duration::ZERO);
    let endpoint_chirho = fixture_chirho.spawn_server_chirho(
        leader_info_chirho(
            &fixture_chirho.target_id_chirho,
            7,
            Some(2_000),
            LeaseTierChirho::MonotonicDecayChirho,
        ),
        Arc::clone(&execution_chirho),
        fixture_chirho.existing_signer_chirho(),
    );
    let port_chirho =
        fixture_chirho.port_chirho(endpoint_chirho, RelayHttpTimeoutsChirho::default(), 25);
    let attempt_chirho = fixture_chirho.attempt_chirho(2_000);
    let wire_chirho = run_relay_chirho(&port_chirho, &attempt_chirho)
        .expect("a signed term refusal is an authenticated response");
    let verified_chirho = attempt_chirho
        .verify_response_chirho(&wire_chirho, &fixture_chirho.roster_chirho)
        .expect("verify term refusal");
    assert_eq!(verified_chirho.actual_term_chirho(), 8);
    assert_eq!(
        verified_chirho.outcome_identity_chirho(),
        Some(RelayRefusalIdentityChirho::RelayOwnerTermChangedChirho.as_str_chirho())
    );
    assert_ne!(
        verified_chirho.outcome_identity_chirho(),
        Some(RelayRefusalIdentityChirho::RelayLeaseExpiredChirho.as_str_chirho())
    );
    assert_eq!(execution_chirho.calls_chirho(), 0);
}

#[test]
fn destination_consumes_request_budget_before_fake_execution_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let execution_chirho = RecordingExecutionChirho::new_chirho(Duration::ZERO);
    let endpoint_chirho = fixture_chirho.spawn_server_chirho(
        leader_info_chirho(
            &fixture_chirho.target_id_chirho,
            7,
            Some(2_000),
            LeaseTierChirho::MonotonicDecayChirho,
        ),
        Arc::clone(&execution_chirho),
        fixture_chirho.existing_signer_chirho(),
    );
    let port_chirho =
        fixture_chirho.port_chirho(endpoint_chirho, RelayHttpTimeoutsChirho::default(), 25);
    let attempt_chirho = fixture_chirho.attempt_chirho(5);
    let wire_chirho = run_relay_chirho(&port_chirho, &attempt_chirho)
        .expect("an authenticated budget refusal returns a signed envelope");
    let verified_chirho = attempt_chirho
        .verify_response_chirho(&wire_chirho, &fixture_chirho.roster_chirho)
        .expect("verify budget refusal");
    assert_eq!(
        verified_chirho.outcome_identity_chirho(),
        Some(RelayRefusalIdentityChirho::RelayLeaseExpiredChirho.as_str_chirho())
    );
    assert_eq!(execution_chirho.calls_chirho(), 0);
}

#[test]
fn response_signature_tamper_is_ambiguous_and_redacts_request_needles_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let execution_chirho = RecordingExecutionChirho::new_chirho(Duration::ZERO);
    let endpoint_chirho = fixture_chirho.spawn_server_chirho(
        leader_info_chirho(
            &fixture_chirho.target_id_chirho,
            7,
            Some(2_000),
            LeaseTierChirho::MonotonicDecayChirho,
        ),
        Arc::clone(&execution_chirho),
        Arc::new(InvalidSignatureSignerChirho {
            node_id_chirho: fixture_chirho.target_id_chirho.clone(),
        }),
    );
    let port_chirho =
        fixture_chirho.port_chirho(endpoint_chirho, RelayHttpTimeoutsChirho::default(), 25);
    let error_chirho = run_relay_chirho(&port_chirho, &fixture_chirho.attempt_chirho(2_000))
        .expect_err("invalid response signature must refuse");
    assert_eq!(
        error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho
    );
    assert_eq!(
        error_chirho.execution_knowledge_chirho(),
        RelayExecutionKnowledgeChirho::MayHaveExecutedChirho
    );
    let display_chirho = error_chirho.to_string();
    assert!(!display_chirho.contains("private-relay-token-chirho"));
    assert!(!display_chirho.contains("needle-chirho"));
    assert_eq!(execution_chirho.calls_chirho(), 1);
}

#[test]
fn refused_connection_is_definite_while_post_execution_timeout_is_ambiguous_chirho() {
    let unavailable_fixture_chirho = RelayFixtureChirho::new_chirho();
    let unused_listener_chirho =
        std::net::TcpListener::bind("127.0.0.1:0").expect("reserve unused port");
    let unused_address_chirho = unused_listener_chirho.local_addr().expect("unused address");
    drop(unused_listener_chirho);
    let unavailable_port_chirho = unavailable_fixture_chirho.port_chirho(
        format!("http://{unused_address_chirho}"),
        RelayHttpTimeoutsChirho {
            connect_chirho: Duration::from_millis(100),
            read_chirho: Duration::from_millis(100),
            write_chirho: Duration::from_millis(100),
            overall_chirho: Duration::from_millis(200),
        },
        25,
    );
    let unavailable_error_chirho = run_relay_chirho(
        &unavailable_port_chirho,
        &unavailable_fixture_chirho.attempt_chirho(2_000),
    )
    .expect_err("connection refusal must fail");
    assert_eq!(
        unavailable_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayOwnerUnavailableChirho
    );
    assert_eq!(
        unavailable_error_chirho.execution_knowledge_chirho(),
        RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho
    );

    let timeout_fixture_chirho = RelayFixtureChirho::new_chirho();
    let execution_chirho = RecordingExecutionChirho::new_chirho(Duration::from_millis(200));
    let endpoint_chirho = timeout_fixture_chirho.spawn_server_chirho(
        leader_info_chirho(
            &timeout_fixture_chirho.target_id_chirho,
            7,
            Some(2_000),
            LeaseTierChirho::MonotonicDecayChirho,
        ),
        Arc::clone(&execution_chirho),
        timeout_fixture_chirho.existing_signer_chirho(),
    );
    let timeout_port_chirho = timeout_fixture_chirho.port_chirho(
        endpoint_chirho,
        RelayHttpTimeoutsChirho {
            connect_chirho: Duration::from_millis(100),
            read_chirho: Duration::from_millis(30),
            write_chirho: Duration::from_millis(100),
            overall_chirho: Duration::from_millis(100),
        },
        10,
    );
    let timeout_error_chirho = run_relay_chirho(
        &timeout_port_chirho,
        &timeout_fixture_chirho.attempt_chirho(2_000),
    )
    .expect_err("response timeout must be ambiguous");
    assert_eq!(
        timeout_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayOutcomeAmbiguousChirho
    );
    assert_eq!(
        timeout_error_chirho.execution_knowledge_chirho(),
        RelayExecutionKnowledgeChirho::MayHaveExecutedChirho
    );
    assert_eq!(execution_chirho.calls_chirho(), 1);
}

#[test]
fn adapter_manifest_and_sources_remain_below_the_serve_and_mutation_layers_chirho() {
    let manifest_chirho = include_str!("../Cargo.toml");
    for forbidden_chirho in [
        "cairn-serve-runtime-chirho",
        "cairn-app-control-chirho",
        "cairn-ledger-host-chirho",
        "cairn-writer-head-chirho =",
        "cairn-chirho =",
    ] {
        assert!(
            !manifest_chirho.contains(forbidden_chirho),
            "write-relay HTTP adapter gained forbidden upward dependency {forbidden_chirho}"
        );
    }
    let sources_chirho = [
        include_str!("lib.rs"),
        include_str!("client_chirho.rs"),
        include_str!("directory_chirho.rs"),
        include_str!("server_chirho.rs"),
    ]
    .join("\n");
    for forbidden_chirho in [
        "with_head_transition_scope_chirho",
        "with_elected_writer_scope_chirho",
        "append_chirho(",
        "save_refs_chirho",
        "tracing::",
        "println!",
    ] {
        assert!(
            !sources_chirho.contains(forbidden_chirho),
            "write-relay HTTP adapter gained forbidden authority/logging surface {forbidden_chirho}"
        );
    }
    let directory_source_chirho = include_str!("directory_chirho.rs");
    assert!(
        directory_source_chirho.contains("#[cfg(test)]\n    pub(crate) fn new_for_test_chirho("),
        "the arbitrary private-IP directory constructor must remain test-only"
    );
    assert!(
        !directory_source_chirho.contains("pub fn new_chirho("),
        "an unqualified production directory constructor would bypass relay mesh evidence"
    );
    assert!(
        directory_source_chirho.contains("pub fn new_from_verified_active_mesh_chirho(")
            && directory_source_chirho.contains("&VerifiedActiveRelayMeshChirho"),
        "the production directory must consume opaque signed-roster and active-WireGuard evidence"
    );
}

#[test]
fn relay_destination_child_process_chirho() {
    if std::env::var_os("CAIRN_RELAY_CHILD_MODE_CHIRHO").is_none() {
        return;
    }
    let target_root_chirho =
        PathBuf::from(std::env::var_os("CAIRN_RELAY_TARGET_ROOT_CHIRHO").expect("target root env"));
    let target_id_chirho = std::env::var("CAIRN_RELAY_TARGET_ID_CHIRHO").expect("target id env");
    let origin_id_chirho = std::env::var("CAIRN_RELAY_ORIGIN_ID_CHIRHO").expect("origin id env");
    let group_digest_chirho =
        std::env::var("CAIRN_RELAY_GROUP_DIGEST_CHIRHO").expect("group digest env");
    let endpoint_file_chirho = PathBuf::from(
        std::env::var_os("CAIRN_RELAY_ENDPOINT_FILE_CHIRHO").expect("endpoint file env"),
    );
    let marker_path_chirho = PathBuf::from(
        std::env::var_os("CAIRN_RELAY_EXECUTION_MARKER_CHIRHO").expect("marker path env"),
    );
    let roster_chirho = Arc::new(
        RelayRosterChirho::new_chirho([origin_id_chirho, target_id_chirho.clone()])
            .expect("child roster"),
    );
    let leadership_chirho =
        StaticWriterElectorChirho::new_chirho(leader_view_chirho(&target_id_chirho, 7, true));
    let signer_chirho: Arc<dyn RelayResponseSignerChirho> = Arc::new(
        ExistingKeyRelayResponseSignerChirho::new_chirho(
            &target_root_chirho,
            target_id_chirho.clone(),
        )
        .expect("child signer"),
    );
    let execution_chirho: Arc<dyn RelayDestinationExecutionPortChirho> =
        Arc::new(ChildProcessExecutionChirho { marker_path_chirho });
    let state_chirho = RelayServerStateChirho::new_chirho(RelayServerConfigChirho {
        group_digest_chirho,
        node_id_chirho: target_id_chirho.clone(),
        roster_chirho: Arc::clone(&roster_chirho),
        leadership_chirho,
        clock_chirho: FakeMonotonicClockChirho::new_chirho(),
        transit_budget_millis_chirho: NonZeroU64::new(10).expect("child transit"),
        signer_chirho,
        execution_chirho,
    })
    .expect("child state");
    let leader_info_chirho = leader_info_chirho(
        &target_id_chirho,
        7,
        Some(2_000),
        LeaseTierChirho::MonotonicDecayChirho,
    );
    let router_chirho = relay_router_chirho(state_chirho).route(
        LEADER_DISCOVERY_PATH_CHIRHO,
        get(move || {
            let leader_info_chirho = leader_info_chirho.clone();
            async move { Json(leader_info_chirho) }
        }),
    );
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").expect("child listener bind");
    let endpoint_temp_chirho = endpoint_file_chirho.with_extension("tmp-chirho");
    std::fs::write(
        &endpoint_temp_chirho,
        format!(
            "http://{}",
            listener_chirho
                .local_addr()
                .expect("child listener address")
        ),
    )
    .expect("publish child endpoint");
    std::fs::rename(endpoint_temp_chirho, endpoint_file_chirho)
        .expect("atomically publish child endpoint");
    serve_relay_router_blocking_chirho(listener_chirho, router_chirho)
        .expect("serve child relay process");
}

#[test]
fn relay_crosses_an_actual_process_boundary_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let coordination_chirho = tempfile::tempdir().expect("child coordination");
    let endpoint_file_chirho = coordination_chirho.path().join("endpoint-chirho.txt");
    let marker_path_chirho = coordination_chirho.path().join("execution-chirho.marker");
    let mut child_chirho = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("tests_chirho::relay_destination_child_process_chirho")
        .arg("--nocapture")
        .env("CAIRN_RELAY_CHILD_MODE_CHIRHO", "1")
        .env(
            "CAIRN_RELAY_TARGET_ROOT_CHIRHO",
            &fixture_chirho.target_path_chirho,
        )
        .env(
            "CAIRN_RELAY_TARGET_ID_CHIRHO",
            &fixture_chirho.target_id_chirho,
        )
        .env(
            "CAIRN_RELAY_ORIGIN_ID_CHIRHO",
            &fixture_chirho.origin_id_chirho,
        )
        .env(
            "CAIRN_RELAY_GROUP_DIGEST_CHIRHO",
            &fixture_chirho.group_digest_chirho,
        )
        .env("CAIRN_RELAY_ENDPOINT_FILE_CHIRHO", &endpoint_file_chirho)
        .env("CAIRN_RELAY_EXECUTION_MARKER_CHIRHO", &marker_path_chirho)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn relay destination process");
    let deadline_chirho = Instant::now() + Duration::from_secs(3);
    while !endpoint_file_chirho.is_file() && Instant::now() < deadline_chirho {
        std::thread::sleep(Duration::from_millis(10));
    }
    let endpoint_chirho =
        std::fs::read_to_string(&endpoint_file_chirho).expect("child endpoint became available");
    let port_chirho =
        fixture_chirho.port_chirho(endpoint_chirho, RelayHttpTimeoutsChirho::default(), 25);
    let attempt_chirho = fixture_chirho.attempt_chirho(2_000);
    let wire_chirho =
        run_relay_chirho(&port_chirho, &attempt_chirho).expect("cross-process relay succeeds");
    let verified_chirho = attempt_chirho
        .verify_response_chirho(&wire_chirho, &fixture_chirho.roster_chirho)
        .expect("verify cross-process response");
    assert_eq!(
        verified_chirho.body_chirho(),
        b"two-process-response-chirho"
    );
    assert_eq!(
        std::fs::read(&marker_path_chirho).expect("child execution marker"),
        b"executed-chirho"
    );
    child_chirho.kill().expect("stop relay destination child");
    let _status_chirho = child_chirho.wait().expect("reap relay destination child");
}
