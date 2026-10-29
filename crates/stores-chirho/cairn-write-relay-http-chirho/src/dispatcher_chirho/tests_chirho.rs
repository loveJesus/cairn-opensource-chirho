// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_write_relay_chirho::{
    CallerIdempotencyKeyChirho, PreparedServedWriteRelayResponseV1Chirho,
    RelayEndToEndHeadersChirho, RelayOutcomeClassChirho, RelayRefusalIdentityChirho,
    ServedWriteRelayFailureChirho, ServedWriteRelayFutureChirho,
    ServedWriteRelayResponseInputChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::{LeadershipChirho, NodeIdChirho};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct StaticLeadershipChirho {
    leadership_chirho: LeadershipChirho,
}

impl FixedGroupLeadershipViewChirho for StaticLeadershipChirho {
    fn current_leadership_chirho(&self) -> LeadershipChirho {
        self.leadership_chirho.clone()
    }
}

struct MutableLeadershipChirho {
    leadership_chirho: Mutex<LeadershipChirho>,
}

impl MutableLeadershipChirho {
    fn new_chirho(leadership_chirho: LeadershipChirho) -> Arc<Self> {
        Arc::new(Self {
            leadership_chirho: Mutex::new(leadership_chirho),
        })
    }

    fn replace_chirho(&self, leadership_chirho: LeadershipChirho) {
        *self
            .leadership_chirho
            .lock()
            .expect("mutable leadership lock") = leadership_chirho;
    }
}

impl FixedGroupLeadershipViewChirho for MutableLeadershipChirho {
    fn current_leadership_chirho(&self) -> LeadershipChirho {
        self.leadership_chirho
            .lock()
            .expect("mutable leadership lock")
            .clone()
    }
}

struct CountingSignerChirho {
    node_id_chirho: String,
    root_chirho: Option<std::path::PathBuf>,
    calls_chirho: AtomicUsize,
}

impl CountingSignerChirho {
    fn real_chirho(root_chirho: &Path, node_id_chirho: String) -> Arc<Self> {
        Arc::new(Self {
            node_id_chirho,
            root_chirho: Some(root_chirho.to_path_buf()),
            calls_chirho: AtomicUsize::new(0),
        })
    }

    fn failing_chirho(node_id_chirho: String) -> Arc<Self> {
        Arc::new(Self {
            node_id_chirho,
            root_chirho: None,
            calls_chirho: AtomicUsize::new(0),
        })
    }

    fn calls_chirho(&self) -> usize {
        self.calls_chirho.load(Ordering::Acquire)
    }
}

impl RelayRequestSignerChirho for CountingSignerChirho {
    fn node_id_chirho(&self) -> &str {
        &self.node_id_chirho
    }

    fn sign_digest_chirho(&self, digest_chirho: &[u8; 32]) -> Result<String> {
        self.calls_chirho.fetch_add(1, Ordering::AcqRel);
        let root_chirho = self
            .root_chirho
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("planted signer refusal"))?;
        let possession_chirho =
            cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho(
                root_chirho,
                digest_chirho,
            )?;
        Ok(possession_chirho.into_signature_hex_chirho())
    }
}

struct SignedResponseRelayChirho {
    target_root_chirho: std::path::PathBuf,
    target_node_id_chirho: String,
    roster_chirho: Arc<RelayRosterChirho>,
    calls_chirho: AtomicUsize,
    observed_request_chirho: Mutex<Option<(String, String, Vec<u8>)>>,
}

impl SignedResponseRelayChirho {
    fn new_chirho(
        target_root_chirho: &Path,
        target_node_id_chirho: String,
        roster_chirho: Arc<RelayRosterChirho>,
    ) -> Arc<Self> {
        Arc::new(Self {
            target_root_chirho: target_root_chirho.to_path_buf(),
            target_node_id_chirho,
            roster_chirho,
            calls_chirho: AtomicUsize::new(0),
            observed_request_chirho: Mutex::new(None),
        })
    }

    fn calls_chirho(&self) -> usize {
        self.calls_chirho.load(Ordering::Acquire)
    }

    fn observed_request_chirho(&self) -> Option<(String, String, Vec<u8>)> {
        self.observed_request_chirho
            .lock()
            .expect("relay observation lock")
            .clone()
    }
}

impl ServedWriteRelayPortChirho for SignedResponseRelayChirho {
    fn relay_one_hop_chirho<'a>(
        &'a self,
        attempt_chirho: &'a PreparedServedWriteRelayAttemptChirho,
    ) -> ServedWriteRelayFutureChirho<'a> {
        Box::pin(async move {
            self.calls_chirho.fetch_add(1, Ordering::AcqRel);
            let request_chirho =
                cairn_write_relay_chirho::decode_and_verify_served_write_relay_request_chirho(
                    attempt_chirho.signed_request_wire_chirho(),
                    attempt_chirho.consistency_group_digest_chirho(),
                    attempt_chirho.target_node_id_chirho(),
                    &self.roster_chirho,
                )?;
            *self
                .observed_request_chirho
                .lock()
                .expect("relay observation lock") = Some((
                request_chirho.method_chirho().to_string(),
                request_chirho.uri_chirho().to_string(),
                request_chirho.body_chirho().to_vec(),
            ));
            let prepared_chirho = PreparedServedWriteRelayResponseV1Chirho::new_chirho(
                ServedWriteRelayResponseInputChirho {
                    request_digest_chirho: attempt_chirho.request_digest_chirho().to_string(),
                    caller_idempotency_key_digest_chirho: attempt_chirho
                        .caller_key_digest_chirho()
                        .to_string(),
                    responder_node_id_chirho: self.target_node_id_chirho.clone(),
                    consistency_group_digest_chirho: attempt_chirho
                        .consistency_group_digest_chirho()
                        .to_string(),
                    actual_term_chirho: attempt_chirho.expected_term_chirho(),
                    outcome_class_chirho: RelayOutcomeClassChirho::ServedResponseChirho,
                    outcome_identity_chirho: None,
                    status_chirho: 202,
                    end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_response_chirho(
                        vec![("content-type".to_string(), "application/json".to_string())],
                    )?,
                    body_chirho: br#"{"relayed_chirho":true}"#.to_vec(),
                },
            )?;
            let possession_chirho =
                cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho(
                    &self.target_root_chirho,
                    &prepared_chirho.signing_digest_chirho(),
                )
                .map_err(|_| RelayContractErrorChirho::request_signing_refused_chirho())?;
            Ok(prepared_chirho
                .into_signed_chirho(possession_chirho.into_signature_hex_chirho())?
                .to_wire_bytes_chirho()?)
        })
    }
}

struct NeverRelayChirho {
    calls_chirho: AtomicUsize,
}

impl NeverRelayChirho {
    fn new_chirho() -> Arc<Self> {
        Arc::new(Self {
            calls_chirho: AtomicUsize::new(0),
        })
    }
}

impl ServedWriteRelayPortChirho for NeverRelayChirho {
    fn relay_one_hop_chirho<'a>(
        &'a self,
        _attempt_chirho: &'a PreparedServedWriteRelayAttemptChirho,
    ) -> ServedWriteRelayFutureChirho<'a> {
        self.calls_chirho.fetch_add(1, Ordering::AcqRel);
        Box::pin(async {
            Err(ServedWriteRelayFailureChirho::ContractChirho(
                RelayContractErrorChirho::owner_unroutable_chirho(),
            ))
        })
    }
}

fn provision_node_chirho(root_chirho: &Path) -> String {
    cairn_signer_chirho::signer_chirho::sign_message_chirho(root_chirho, b"dispatcher-seed-chirho")
        .expect("provision dispatcher node");
    cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho(root_chirho)
        .expect("dispatcher node id")
}

fn leadership_chirho(
    is_leader_chirho: bool,
    leader_node_id_chirho: &str,
    lease_valid_chirho: bool,
) -> Arc<dyn FixedGroupLeadershipViewChirho> {
    Arc::new(StaticLeadershipChirho {
        leadership_chirho: LeadershipChirho {
            is_leader_chirho,
            leader_id_chirho: Some(NodeIdChirho(leader_node_id_chirho.to_string())),
            term_chirho: 11,
            lease_valid_chirho,
        },
    })
}

fn input_chirho() -> ServedWriteDispatchInputChirho {
    ServedWriteDispatchInputChirho {
        ingress_admission_chirho: Some(
            cairn_write_relay_chirho::RelayIngressAdmissionChirho::new_chirho(
                60_000, 60, 8_388_608, 600, 67_108_864,
            )
            .expect("fixture ingress"),
        ),
        caller_idempotency_key_chirho: CallerIdempotencyKeyChirho::new_chirho(
            "dispatcher-operation-0001-chirho",
        )
        .expect("caller key"),
        method_chirho: "POST".to_string(),
        uri_chirho: "/app-chirho/credits-demo-chirho/spend-chirho".to_string(),
        end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_request_chirho(vec![(
            "content-type".to_string(),
            "application/json".to_string(),
        )])
        .expect("request headers"),
        body_chirho: br#"{"amount_chirho":1}"#.to_vec(),
    }
}

#[tokio::test]
async fn live_local_owner_executes_without_signing_or_transport_chirho() {
    let root_chirho = tempfile::tempdir().expect("local signer root");
    let local_node_chirho = provision_node_chirho(root_chirho.path());
    let group_chirho = blake3::hash(b"dispatcher-group-chirho")
        .to_hex()
        .to_string();
    let roster_chirho =
        Arc::new(RelayRosterChirho::new_chirho([local_node_chirho.clone()]).unwrap());
    let signer_chirho =
        CountingSignerChirho::real_chirho(root_chirho.path(), local_node_chirho.clone());
    let relay_chirho = NeverRelayChirho::new_chirho();
    let dispatcher_chirho = HttpServedWriteDispatchPortChirho::new_chirho(
        local_node_chirho.clone(),
        group_chirho,
        roster_chirho,
        leadership_chirho(true, &local_node_chirho, true),
        signer_chirho.clone(),
        relay_chirho.clone(),
        LocalRelayDispatchPolicyChirho::new_chirho(NonZeroU64::new(500).unwrap(), {
            let readiness_chirho = LocalRelayAuthorityReadinessChirho::new_chirho();
            readiness_chirho.mark_ready_chirho();
            readiness_chirho
        }),
    )
    .unwrap();

    assert!(matches!(
        dispatcher_chirho.dispatch_chirho(input_chirho()).await,
        Ok(ServedWriteDispatchOutcomeChirho::ExecuteLocallyChirho)
    ));
    assert_eq!(signer_chirho.calls_chirho(), 0);
    assert_eq!(relay_chirho.calls_chirho.load(Ordering::Acquire), 0);
}

#[test]
fn local_read_witness_requires_ready_current_leased_owner_and_same_term_chirho() {
    let root_chirho = tempfile::tempdir().expect("local read signer root");
    let remote_root_chirho = tempfile::tempdir().expect("remote read signer root");
    let local_node_chirho = provision_node_chirho(root_chirho.path());
    let remote_node_chirho = provision_node_chirho(remote_root_chirho.path());
    let group_chirho = blake3::hash(b"local-read-witness-group-chirho")
        .to_hex()
        .to_string();
    let roster_chirho = Arc::new(
        RelayRosterChirho::new_chirho([local_node_chirho.clone(), remote_node_chirho.clone()])
            .expect("two-node local read roster"),
    );
    let signer_chirho =
        CountingSignerChirho::real_chirho(root_chirho.path(), local_node_chirho.clone());
    let relay_chirho = NeverRelayChirho::new_chirho();
    let leadership_chirho = MutableLeadershipChirho::new_chirho(LeadershipChirho {
        is_leader_chirho: true,
        leader_id_chirho: Some(NodeIdChirho(local_node_chirho.clone())),
        term_chirho: 11,
        lease_valid_chirho: true,
    });
    let readiness_chirho = LocalRelayAuthorityReadinessChirho::new_chirho();
    let dispatcher_chirho = HttpServedWriteDispatchPortChirho::new_chirho(
        local_node_chirho.clone(),
        group_chirho,
        roster_chirho,
        leadership_chirho.clone(),
        signer_chirho.clone(),
        relay_chirho.clone(),
        LocalRelayDispatchPolicyChirho::new_chirho(
            NonZeroU64::new(500).unwrap(),
            readiness_chirho.clone(),
        ),
    )
    .expect("local read dispatcher");

    let unready_error_chirho = dispatcher_chirho
        .begin_local_read_chirho()
        .expect_err("an unready resident must not license a local read");
    assert_eq!(
        unready_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayLocalAuthorityUnavailableChirho
    );
    assert_ne!(
        unready_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayLeaseExpiredChirho
    );

    readiness_chirho.mark_ready_chirho();
    let witness_chirho = dispatcher_chirho
        .begin_local_read_chirho()
        .expect("live local owner begins read");
    assert_eq!(witness_chirho.local_node_id_chirho(), local_node_chirho);
    assert_eq!(witness_chirho.term_chirho(), 11);
    assert_eq!(signer_chirho.calls_chirho(), 0);
    assert_eq!(relay_chirho.calls_chirho.load(Ordering::Acquire), 0);

    leadership_chirho.replace_chirho(LeadershipChirho {
        is_leader_chirho: true,
        leader_id_chirho: Some(NodeIdChirho(local_node_chirho.clone())),
        term_chirho: 11,
        lease_valid_chirho: false,
    });
    let expired_error_chirho = dispatcher_chirho
        .begin_local_read_chirho()
        .expect_err("an expired local owner must not license a read");
    assert_eq!(
        expired_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayLeaseExpiredChirho
    );
    assert_ne!(
        expired_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayOwnerTermChangedChirho
    );

    leadership_chirho.replace_chirho(LeadershipChirho {
        is_leader_chirho: true,
        leader_id_chirho: Some(NodeIdChirho(local_node_chirho.clone())),
        term_chirho: 12,
        lease_valid_chirho: true,
    });
    let changed_error_chirho = dispatcher_chirho
        .confirm_local_read_chirho(&witness_chirho)
        .expect_err("a new term must invalidate the read witness");
    assert_eq!(
        changed_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayOwnerTermChangedChirho
    );

    leadership_chirho.replace_chirho(LeadershipChirho {
        is_leader_chirho: false,
        leader_id_chirho: Some(NodeIdChirho(remote_node_chirho)),
        term_chirho: 12,
        lease_valid_chirho: true,
    });
    let remote_error_chirho = dispatcher_chirho
        .begin_local_read_chirho()
        .expect_err("a remote owner must not license a local read");
    assert_eq!(
        remote_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayLocalAuthorityUnavailableChirho
    );
    assert_eq!(signer_chirho.calls_chirho(), 0);
    assert_eq!(relay_chirho.calls_chirho.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn local_owner_refuses_until_the_resident_authority_is_installed_chirho() {
    let root_chirho = tempfile::tempdir().expect("local signer root");
    let local_node_chirho = provision_node_chirho(root_chirho.path());
    let group_chirho = blake3::hash(b"dispatcher-group-chirho")
        .to_hex()
        .to_string();
    let roster_chirho =
        Arc::new(RelayRosterChirho::new_chirho([local_node_chirho.clone()]).unwrap());
    let signer_chirho =
        CountingSignerChirho::real_chirho(root_chirho.path(), local_node_chirho.clone());
    let relay_chirho = NeverRelayChirho::new_chirho();
    let readiness_chirho = LocalRelayAuthorityReadinessChirho::new_chirho();
    let dispatcher_chirho = HttpServedWriteDispatchPortChirho::new_chirho(
        local_node_chirho.clone(),
        group_chirho,
        roster_chirho,
        leadership_chirho(true, &local_node_chirho, true),
        signer_chirho.clone(),
        relay_chirho.clone(),
        LocalRelayDispatchPolicyChirho::new_chirho(
            NonZeroU64::new(500).unwrap(),
            readiness_chirho.clone(),
        ),
    )
    .unwrap();

    let error_chirho = match dispatcher_chirho.dispatch_chirho(input_chirho()).await {
        Ok(_) => panic!("uninstalled local authority must refuse"),
        Err(error_chirho) => error_chirho,
    };
    assert_eq!(
        error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayLocalAuthorityUnavailableChirho
    );
    assert_ne!(
        error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayLeaseExpiredChirho
    );
    assert_eq!(signer_chirho.calls_chirho(), 0);
    assert_eq!(relay_chirho.calls_chirho.load(Ordering::Acquire), 0);

    readiness_chirho.mark_ready_chirho();
    assert!(matches!(
        dispatcher_chirho.dispatch_chirho(input_chirho()).await,
        Ok(ServedWriteDispatchOutcomeChirho::ExecuteLocallyChirho)
    ));
}

#[tokio::test]
async fn expired_local_owner_refuses_before_signing_or_transport_chirho() {
    let root_chirho = tempfile::tempdir().expect("local signer root");
    let local_node_chirho = provision_node_chirho(root_chirho.path());
    let group_chirho = blake3::hash(b"dispatcher-group-chirho")
        .to_hex()
        .to_string();
    let roster_chirho =
        Arc::new(RelayRosterChirho::new_chirho([local_node_chirho.clone()]).unwrap());
    let signer_chirho =
        CountingSignerChirho::real_chirho(root_chirho.path(), local_node_chirho.clone());
    let relay_chirho = NeverRelayChirho::new_chirho();
    let dispatcher_chirho = HttpServedWriteDispatchPortChirho::new_chirho(
        local_node_chirho.clone(),
        group_chirho,
        roster_chirho,
        leadership_chirho(true, &local_node_chirho, false),
        signer_chirho.clone(),
        relay_chirho.clone(),
        LocalRelayDispatchPolicyChirho::new_chirho(NonZeroU64::new(500).unwrap(), {
            let readiness_chirho = LocalRelayAuthorityReadinessChirho::new_chirho();
            readiness_chirho.mark_ready_chirho();
            readiness_chirho
        }),
    )
    .unwrap();

    let error_chirho = match dispatcher_chirho.dispatch_chirho(input_chirho()).await {
        Ok(_) => panic!("expired local owner must refuse"),
        Err(error_chirho) => error_chirho,
    };
    assert_eq!(
        error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayLeaseExpiredChirho
    );
    assert_ne!(
        error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayOwnerTermChangedChirho
    );
    assert_eq!(signer_chirho.calls_chirho(), 0);
    assert_eq!(relay_chirho.calls_chirho.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn remote_owner_receives_one_signed_request_and_returns_one_verified_response_chirho() {
    let origin_root_chirho = tempfile::tempdir().expect("origin signer root");
    let target_root_chirho = tempfile::tempdir().expect("target signer root");
    let origin_node_chirho = provision_node_chirho(origin_root_chirho.path());
    let target_node_chirho = provision_node_chirho(target_root_chirho.path());
    let group_chirho = blake3::hash(b"dispatcher-group-chirho")
        .to_hex()
        .to_string();
    let roster_chirho = Arc::new(
        RelayRosterChirho::new_chirho([origin_node_chirho.clone(), target_node_chirho.clone()])
            .unwrap(),
    );
    let signer_chirho =
        CountingSignerChirho::real_chirho(origin_root_chirho.path(), origin_node_chirho.clone());
    let relay_chirho = SignedResponseRelayChirho::new_chirho(
        target_root_chirho.path(),
        target_node_chirho.clone(),
        roster_chirho.clone(),
    );
    let dispatcher_chirho = HttpServedWriteDispatchPortChirho::new_chirho(
        origin_node_chirho,
        group_chirho,
        roster_chirho,
        leadership_chirho(false, &target_node_chirho, false),
        signer_chirho.clone(),
        relay_chirho.clone(),
        LocalRelayDispatchPolicyChirho::new_chirho(
            NonZeroU64::new(500).unwrap(),
            LocalRelayAuthorityReadinessChirho::new_chirho(),
        ),
    )
    .unwrap();

    assert_eq!(
        dispatcher_chirho
            .ingress_scope_chirho()
            .unwrap()
            .origin_count_chirho(),
        2
    );
    let mut missing_chirho = input_chirho();
    missing_chirho.ingress_admission_chirho = None;
    let error_chirho = match dispatcher_chirho.dispatch_chirho(missing_chirho).await {
        Err(error_chirho) => error_chirho,
        Ok(_) => panic!("remote dispatch without admission must refuse"),
    };
    assert_eq!(
        error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayIngressAdmissionInvalidChirho
    );
    assert_eq!(signer_chirho.calls_chirho(), 0);
    assert_eq!(relay_chirho.calls_chirho(), 0);

    let outcome_chirho = dispatcher_chirho
        .dispatch_chirho(input_chirho())
        .await
        .expect("remote dispatch");
    let ServedWriteDispatchOutcomeChirho::RelayedChirho(response_chirho) = outcome_chirho else {
        panic!("remote owner must return a verified relay response");
    };
    assert_eq!(response_chirho.status_chirho(), 202);
    assert_eq!(response_chirho.body_chirho(), br#"{"relayed_chirho":true}"#);
    assert_eq!(signer_chirho.calls_chirho(), 1);
    assert_eq!(relay_chirho.calls_chirho(), 1);
    assert_eq!(
        relay_chirho.observed_request_chirho(),
        Some((
            "POST".to_string(),
            "/app-chirho/credits-demo-chirho/spend-chirho".to_string(),
            br#"{"amount_chirho":1}"#.to_vec(),
        ))
    );
}

#[tokio::test]
async fn origin_signer_failure_has_its_own_pre_execution_identity_chirho() {
    let origin_root_chirho = tempfile::tempdir().expect("origin signer root");
    let target_root_chirho = tempfile::tempdir().expect("target signer root");
    let origin_node_chirho = provision_node_chirho(origin_root_chirho.path());
    let target_node_chirho = provision_node_chirho(target_root_chirho.path());
    let group_chirho = blake3::hash(b"dispatcher-group-chirho")
        .to_hex()
        .to_string();
    let roster_chirho = Arc::new(
        RelayRosterChirho::new_chirho([origin_node_chirho.clone(), target_node_chirho.clone()])
            .unwrap(),
    );
    let signer_chirho = CountingSignerChirho::failing_chirho(origin_node_chirho.clone());
    let relay_chirho = NeverRelayChirho::new_chirho();
    let dispatcher_chirho = HttpServedWriteDispatchPortChirho::new_chirho(
        origin_node_chirho,
        group_chirho,
        roster_chirho,
        leadership_chirho(false, &target_node_chirho, false),
        signer_chirho.clone(),
        relay_chirho.clone(),
        LocalRelayDispatchPolicyChirho::new_chirho(
            NonZeroU64::new(500).unwrap(),
            LocalRelayAuthorityReadinessChirho::new_chirho(),
        ),
    )
    .unwrap();

    let error_chirho = match dispatcher_chirho.dispatch_chirho(input_chirho()).await {
        Ok(_) => panic!("planted signer failure must refuse"),
        Err(error_chirho) => error_chirho,
    };
    assert_eq!(
        error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayRequestSignatureInvalidChirho
    );
    assert_ne!(
        error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayOwnerUnroutableChirho
    );
    assert_eq!(signer_chirho.calls_chirho(), 1);
    assert_eq!(relay_chirho.calls_chirho.load(Ordering::Acquire), 0);
}
