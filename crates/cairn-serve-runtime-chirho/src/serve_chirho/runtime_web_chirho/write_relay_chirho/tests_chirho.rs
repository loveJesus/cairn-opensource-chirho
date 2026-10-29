// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

#[path = "fence_read_consumer_tests_chirho.rs"]
mod fence_read_consumer_tests_chirho;
#[path = "ingress_tests_chirho.rs"]
mod ingress_tests_chirho;
use cairn_write_relay_chirho::{
    decode_and_verify_served_write_relay_request_chirho,
    decode_and_verify_served_write_relay_response_chirho,
    relay_tenant_consistency_group_digest_chirho, PreparedServedWriteRelayRequestV1Chirho,
    PreparedServedWriteRelayResponseV1Chirho, RelayContractErrorChirho, RelayEndToEndHeadersChirho,
    RelayRosterChirho, ServedWriteDispatchFutureChirho, ServedWriteDispatchPortChirho,
    ServedWriteRelayRequestInputChirho, ServedWriteRelayResponseInputChirho,
};
use ed25519_dalek::{Signer as _, SigningKey};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedDispatchChirho {
    caller_key_chirho: String,
    method_chirho: String,
    uri_chirho: String,
    body_chirho: Vec<u8>,
}

enum StubDispatchOutcomeChirho {
    ExecuteLocallyChirho,
    OwnerUnknownChirho,
}

struct StubDispatchChirho {
    calls_chirho: AtomicUsize,
    records_chirho: Mutex<Vec<RecordedDispatchChirho>>,
    outcome_chirho: StubDispatchOutcomeChirho,
}

struct TestPlatformRootChirho(PathBuf);

impl TestPlatformRootChirho {
    fn new_chirho(label_chirho: &str) -> Self {
        let nonce_chirho = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        let path_chirho = std::env::temp_dir().join(format!(
            "cairn-write-relay-{label_chirho}-{}-{nonce_chirho}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path_chirho).expect("test platform root");
        Self(path_chirho)
    }

    fn path_chirho(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestPlatformRootChirho {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl StubDispatchChirho {
    fn new_chirho(outcome_chirho: StubDispatchOutcomeChirho) -> Arc<Self> {
        Arc::new(Self {
            calls_chirho: AtomicUsize::new(0),
            records_chirho: Mutex::new(Vec::new()),
            outcome_chirho,
        })
    }

    fn calls_chirho(&self) -> usize {
        self.calls_chirho.load(Ordering::Acquire)
    }

    fn records_chirho(&self) -> Vec<RecordedDispatchChirho> {
        self.records_chirho
            .lock()
            .expect("stub dispatch record lock")
            .clone()
    }
}

impl ServedWriteDispatchPortChirho for StubDispatchChirho {
    fn ingress_scope_chirho(&self) -> Option<cairn_write_relay_chirho::RelayIngressScopeChirho> {
        let origin_chirho = encode_hex_chirho(
            SigningKey::from_bytes(&[0x31; 32])
                .verifying_key()
                .as_bytes(),
        );
        let target_chirho = encode_hex_chirho(
            SigningKey::from_bytes(&[0x52; 32])
                .verifying_key()
                .as_bytes(),
        );
        Some(
            cairn_write_relay_chirho::RelayIngressScopeChirho::new_chirho(
                target_chirho.clone(),
                relay_tenant_consistency_group_digest_chirho("relay-test-tenant-chirho").unwrap(),
                &RelayRosterChirho::new_chirho([origin_chirho, target_chirho]).unwrap(),
            )
            .unwrap(),
        )
    }

    fn dispatch_chirho<'a>(
        &'a self,
        input_chirho: ServedWriteDispatchInputChirho,
    ) -> ServedWriteDispatchFutureChirho<'a> {
        Box::pin(async move {
            self.calls_chirho.fetch_add(1, Ordering::AcqRel);
            self.records_chirho
                .lock()
                .expect("stub dispatch record lock")
                .push(RecordedDispatchChirho {
                    caller_key_chirho: input_chirho
                        .caller_idempotency_key_chirho
                        .as_str_chirho()
                        .to_string(),
                    method_chirho: input_chirho.method_chirho,
                    uri_chirho: input_chirho.uri_chirho,
                    body_chirho: input_chirho.body_chirho,
                });
            match self.outcome_chirho {
                StubDispatchOutcomeChirho::ExecuteLocallyChirho => {
                    Ok(ServedWriteDispatchOutcomeChirho::ExecuteLocallyChirho)
                }
                StubDispatchOutcomeChirho::OwnerUnknownChirho => {
                    Err(RelayContractErrorChirho::owner_unknown_chirho().into())
                }
            }
        })
    }
}

fn tenant_root_chirho(platform_root_chirho: &Path) -> PathBuf {
    cairn_chirho::tenant_chirho::root_for_tenant_chirho(
        platform_root_chirho,
        &cairn_chirho::tenant_chirho::TenantIdChirho::TenantChirho(
            "relay-test-tenant-chirho".to_string(),
        ),
    )
    .expect("tenant root")
}

fn state_with_dispatch_chirho(
    root_chirho: &Path,
    dispatch_chirho: Arc<dyn ServedWriteDispatchPortChirho>,
) -> AppStateChirho {
    state_with_dispatch_and_limits_chirho(
        root_chirho,
        dispatch_chirho,
        super::super::ServedRequestAbuseLimitsChirho::default(),
    )
}

fn state_with_dispatch_and_limits_chirho(
    root_chirho: &Path,
    dispatch_chirho: Arc<dyn ServedWriteDispatchPortChirho>,
    served_request_limits_chirho: super::super::ServedRequestAbuseLimitsChirho,
) -> AppStateChirho {
    super::super::app_state_for_runtime_root_with_effect_runtime_chirho(
        root_chirho,
        super::super::RuntimeAppStateOptionsChirho {
            inflight_limit_chirho: 8,
            auth_tokens_chirho: super::super::ServeAuthTokensChirho::default(),
            domain_routing_enabled_chirho: false,
            served_request_limits_chirho,
            projection_read_chirho: None,
            postgres_effect_chirho: None,
            llm_served_chirho: None,
            write_dispatch_chirho: Some(dispatch_chirho),
            local_read_authority_chirho: None,
            write_destination_slot_chirho: None,
        },
    )
    .expect("relay test app state")
}

fn authenticated_credits_headers_chirho(root_chirho: &Path) -> HeaderMap {
    let owner_chirho = cairn_chirho::identity_chirho::register_identity_chirho(
        root_chirho,
        cairn_chirho::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .expect("credits owner");
    let user_secret_chirho = "relay-follower-user-secret-chirho";
    let user_chirho = cairn_chirho::identity_chirho::register_identity_with_credential_chirho(
        root_chirho,
        cairn_chirho::identity_chirho::PrincipalKindChirho::UserChirho,
        user_secret_chirho,
    )
    .expect("credits user");
    let dag_chirho = cairn_chirho::store_chirho::put_object_chirho(
        root_chirho,
        &cairn_chirho::model_chirho::DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .expect("empty credits fixture DAG");
    cairn_chirho::app_chirho::deploy_app_chirho(
        root_chirho,
        CREDITS_APP_CHIRHO,
        dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .expect("deploy credits fixture before geo latch");
    let client_chirho = cairn_chirho::oauth_chirho::register_client_chirho(
        root_chirho,
        CREDITS_APP_CHIRHO,
        &owner_chirho.principal_chirho,
    )
    .expect("credits OAuth client");
    let token_chirho = cairn_chirho::oauth_chirho::issue_scoped_token_with_rate_limit_chirho(
        root_chirho,
        &user_chirho.principal_chirho,
        user_secret_chirho,
        &client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
        Some(cairn_chirho::oauth_chirho::ScopedTokenRateLimitChirho {
            window_ms_chirho: 60_000,
            max_invokes_chirho: 10,
            device_id_chirho: Some("relay-follower-device-chirho".to_string()),
        }),
    )
    .expect("credits scoped token");
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {}", token_chirho.token_chirho)
            .parse()
            .expect("visible bearer header"),
    );
    headers_chirho.insert(
        CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("authenticated-follower-operation-0001-chirho"),
    );
    headers_chirho
}

fn encode_hex_chirho(bytes_chirho: &[u8]) -> String {
    let mut encoded_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        use std::fmt::Write as _;
        write!(&mut encoded_chirho, "{byte_chirho:02x}").expect("hex encoding into String");
    }
    encoded_chirho
}

fn verified_relay_request_chirho(
    body_chirho: Vec<u8>,
) -> cairn_write_relay_chirho::VerifiedServedWriteRelayRequestChirho {
    verified_relay_request_with_ingress_chirho(
        body_chirho,
        Some(RelayIngressAdmissionChirho::new_chirho(60_000, 60, 1, 300, 1).unwrap()),
    )
}

fn verified_relay_request_with_ingress_chirho(
    body_chirho: Vec<u8>,
    ingress_admission_chirho: Option<RelayIngressAdmissionChirho>,
) -> cairn_write_relay_chirho::VerifiedServedWriteRelayRequestChirho {
    verified_relay_request_with_headers_chirho(
        body_chirho,
        ingress_admission_chirho,
        RelayEndToEndHeadersChirho::try_request_chirho([]).unwrap(),
    )
}

fn verified_relay_request_with_headers_chirho(
    body_chirho: Vec<u8>,
    ingress_admission_chirho: Option<RelayIngressAdmissionChirho>,
    end_to_end_headers_chirho: RelayEndToEndHeadersChirho,
) -> cairn_write_relay_chirho::VerifiedServedWriteRelayRequestChirho {
    let origin_key_chirho = SigningKey::from_bytes(&[0x31; 32]);
    let target_key_chirho = SigningKey::from_bytes(&[0x52; 32]);
    let origin_id_chirho = encode_hex_chirho(origin_key_chirho.verifying_key().as_bytes());
    let target_id_chirho = encode_hex_chirho(target_key_chirho.verifying_key().as_bytes());
    let group_digest_chirho =
        relay_tenant_consistency_group_digest_chirho("relay-test-tenant-chirho")
            .expect("canonical tenant relay group");
    let roster_chirho =
        RelayRosterChirho::new_chirho(vec![origin_id_chirho.clone(), target_id_chirho.clone()])
            .expect("two-node relay roster");
    let prepared_chirho =
        PreparedServedWriteRelayRequestV1Chirho::new_chirho(ServedWriteRelayRequestInputChirho {
            ingress_admission_chirho,
            origin_node_id_chirho: origin_id_chirho,
            target_node_id_chirho: target_id_chirho.clone(),
            consistency_group_digest_chirho: group_digest_chirho.clone(),
            expected_term_chirho: 7,
            caller_idempotency_key_chirho: CallerIdempotencyKeyChirho::new_chirho(
                "destination-admission-operation-0001-chirho",
            )
            .expect("bounded caller key"),
            method_chirho: "POST".to_string(),
            uri_chirho: "/app-chirho/credits-demo-chirho/spend-chirho".to_string(),
            end_to_end_headers_chirho,
            body_chirho,
            relay_budget_remaining_millis_chirho: 2_500,
        })
        .expect("prepared relay request");
    let signature_chirho = origin_key_chirho.sign(&prepared_chirho.signing_digest_chirho());
    let request_chirho = prepared_chirho
        .into_signed_chirho(encode_hex_chirho(&signature_chirho.to_bytes()))
        .expect("signed relay request");
    decode_and_verify_served_write_relay_request_chirho(
        &request_chirho
            .to_wire_bytes_chirho()
            .expect("bounded relay request"),
        &group_digest_chirho,
        &target_id_chirho,
        &roster_chirho,
    )
    .expect("verified destination-bound relay request")
}

fn verified_relay_response_for_outcome_chirho(
    outcome_class_chirho: RelayOutcomeClassChirho,
    outcome_identity_chirho: Option<&str>,
    status_chirho: u16,
    body_chirho: Vec<u8>,
) -> VerifiedServedWriteRelayResponseChirho {
    let request_chirho = verified_relay_request_chirho(b"response-fixture-chirho".to_vec());
    let origin_key_chirho = SigningKey::from_bytes(&[0x31; 32]);
    let target_key_chirho = SigningKey::from_bytes(&[0x52; 32]);
    let origin_id_chirho = encode_hex_chirho(origin_key_chirho.verifying_key().as_bytes());
    let target_id_chirho = encode_hex_chirho(target_key_chirho.verifying_key().as_bytes());
    let group_digest_chirho =
        relay_tenant_consistency_group_digest_chirho("relay-test-tenant-chirho")
            .expect("canonical tenant relay group");
    let roster_chirho =
        RelayRosterChirho::new_chirho(vec![origin_id_chirho, target_id_chirho.clone()])
            .expect("two-node relay roster");
    let prepared_chirho =
        PreparedServedWriteRelayResponseV1Chirho::new_chirho(ServedWriteRelayResponseInputChirho {
            request_digest_chirho: request_chirho.request_digest_chirho().to_string(),
            caller_idempotency_key_digest_chirho: request_chirho
                .caller_idempotency_key_chirho()
                .digest_hex_chirho(),
            responder_node_id_chirho: target_id_chirho.clone(),
            consistency_group_digest_chirho: group_digest_chirho.clone(),
            actual_term_chirho: 7,
            outcome_class_chirho,
            outcome_identity_chirho: outcome_identity_chirho.map(str::to_string),
            status_chirho,
            end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_response_chirho(vec![(
                "content-type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )])
            .expect("reviewed response header"),
            body_chirho,
        })
        .expect("semantically valid response");
    let signature_chirho = target_key_chirho.sign(&prepared_chirho.signing_digest_chirho());
    let signed_chirho = prepared_chirho
        .into_signed_chirho(encode_hex_chirho(&signature_chirho.to_bytes()))
        .expect("signed response");
    decode_and_verify_served_write_relay_response_chirho(
        &signed_chirho
            .to_wire_bytes_chirho()
            .expect("bounded wire response"),
        request_chirho.request_digest_chirho(),
        &request_chirho
            .caller_idempotency_key_chirho()
            .digest_hex_chirho(),
        &group_digest_chirho,
        &target_id_chirho,
        &roster_chirho,
    )
    .expect("verified response")
}

async fn response_text_chirho(response_chirho: Response) -> (StatusCode, String) {
    let status_chirho = response_chirho.status();
    let body_chirho = to_bytes(
        response_chirho.into_body(),
        RELAY_RESPONSE_BODY_MAX_BYTES_CHIRHO,
    )
    .await
    .expect("bounded response body");
    (
        status_chirho,
        String::from_utf8(body_chirho.to_vec()).expect("UTF-8 refusal body"),
    )
}

#[tokio::test]
async fn final_http_conversion_preserves_or_names_every_signed_outcome_chirho() {
    let ambiguous_chirho = verified_relay_response_for_outcome_chirho(
        RelayOutcomeClassChirho::RelayRefusalChirho,
        Some(
            RelayRefusalIdentityChirho::RelayResponseUnavailableAfterExecutionChirho
                .as_str_chirho(),
        ),
        StatusCode::SERVICE_UNAVAILABLE.as_u16(),
        Vec::new(),
    );
    let (ambiguous_status_chirho, ambiguous_body_chirho) = response_text_chirho(
        verified_relay_response_chirho(ambiguous_chirho, relay_named_refusal_response_chirho),
    )
    .await;
    assert_eq!(ambiguous_status_chirho, StatusCode::GATEWAY_TIMEOUT);
    assert!(
        ambiguous_body_chirho.contains("RelayResponseUnavailableAfterExecutionChirho"),
        "{ambiguous_body_chirho}"
    );

    let pre_execution_chirho = verified_relay_response_for_outcome_chirho(
        RelayOutcomeClassChirho::RelayRefusalChirho,
        Some(RelayRefusalIdentityChirho::RelayOwnerTermChangedChirho.as_str_chirho()),
        StatusCode::SERVICE_UNAVAILABLE.as_u16(),
        Vec::new(),
    );
    let (pre_execution_status_chirho, pre_execution_body_chirho) = response_text_chirho(
        verified_relay_response_chirho(pre_execution_chirho, relay_named_refusal_response_chirho),
    )
    .await;
    assert_eq!(pre_execution_status_chirho, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        pre_execution_body_chirho.contains("RelayOwnerTermChangedChirho"),
        "{pre_execution_body_chirho}"
    );

    let door_body_chirho = b"error: ElectedAuthorityDeposedChirho: no mutation occurred\n".to_vec();
    let door_chirho = verified_relay_response_for_outcome_chirho(
        RelayOutcomeClassChirho::DoorRefusalChirho,
        Some("ElectedAuthorityDeposedChirho"),
        StatusCode::CONFLICT.as_u16(),
        door_body_chirho.clone(),
    );
    let response_chirho =
        verified_relay_response_chirho(door_chirho, relay_named_refusal_response_chirho);
    assert_eq!(
        response_chirho.headers().get("content-type").unwrap(),
        "text/plain; charset=utf-8"
    );
    let (door_status_chirho, rendered_door_body_chirho) =
        response_text_chirho(response_chirho).await;
    assert_eq!(door_status_chirho, StatusCode::CONFLICT);
    assert_eq!(rendered_door_body_chirho.as_bytes(), door_body_chirho);
}

#[tokio::test]
async fn relay_only_follower_router_is_default_deny_outside_the_first_vertical_chirho() {
    for (method_chirho, path_chirho) in [
        (Method::POST, "/auth-chirho/token-chirho"),
        (
            Method::POST,
            "/app-state-chirho/user-chirho/example-chirho/demo-chirho/rollback-chirho",
        ),
        (
            Method::POST,
            "/resource-policy-chirho/user-chirho/example-chirho/demo-chirho/apply-chirho",
        ),
        (Method::POST, "/publish-chirho"),
        (Method::GET, "/ssr-chirho/credits-demo-chirho"),
        (Method::GET, "/new-unclassified-surface-chirho"),
        (Method::PUT, CREDITS_SPEND_PATH_CHIRHO),
    ] {
        let response_chirho = relay_only_follower_route_refusal_chirho(&method_chirho, path_chirho)
            .expect("every route outside the exact first vertical must refuse by default");
        let (status_chirho, body_chirho) = response_text_chirho(response_chirho).await;
        assert_eq!(status_chirho, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            body_chirho.contains("RelayMutationFamilyUnconvertedChirho"),
            "{method_chirho} {path_chirho} returned {body_chirho}"
        );
        assert!(
            !body_chirho.contains("RelayCallerKeyInvalidChirho"),
            "an unconverted surface must refuse before interpreting a caller key: {body_chirho}"
        );
    }

    for (method_chirho, path_chirho) in [
        (Method::GET, "/healthz"),
        (Method::HEAD, "/healthz-chirho"),
        (Method::GET, CREDITS_SPEND_PATH_CHIRHO),
        (Method::POST, CREDITS_SPEND_PATH_CHIRHO),
    ] {
        assert!(
            relay_only_follower_route_refusal_chirho(&method_chirho, path_chirho).is_none(),
            "{method_chirho} {path_chirho} is part of the exact relay-only allowlist"
        );
    }
}

fn snapshot_files_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit_chirho(
        root_chirho: &Path,
        current_chirho: &Path,
        output_chirho: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) {
        let mut entries_chirho = std::fs::read_dir(current_chirho)
            .expect("snapshot directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("snapshot entries");
        entries_chirho.sort_by_key(|entry_chirho| entry_chirho.file_name());
        for entry_chirho in entries_chirho {
            let path_chirho = entry_chirho.path();
            let file_type_chirho = entry_chirho.file_type().expect("snapshot file type");
            if file_type_chirho.is_dir() {
                visit_chirho(root_chirho, &path_chirho, output_chirho);
            } else if file_type_chirho.is_file() {
                output_chirho.insert(
                    path_chirho
                        .strip_prefix(root_chirho)
                        .expect("snapshot relative path")
                        .to_path_buf(),
                    std::fs::read(path_chirho).expect("snapshot file"),
                );
            }
        }
    }

    let mut output_chirho = BTreeMap::new();
    visit_chirho(root_chirho, root_chirho, &mut output_chirho);
    output_chirho
}

#[test]
fn direct_reentry_parses_canonical_named_routes_not_execution_authority_chirho() {
    let credits_chirho: Uri = "/app-chirho/credits-demo-chirho/spend-chirho?bounded=1"
        .parse()
        .unwrap();
    assert_eq!(
        direct_app_route_from_uri_chirho(&credits_chirho),
        Some((
            "credits-demo-chirho".to_string(),
            "spend-chirho".to_string()
        ))
    );
    let named_chirho: Uri = "/app-chirho/another-app-chirho/view-chirho"
        .parse()
        .unwrap();
    assert_eq!(
        direct_app_route_from_uri_chirho(&named_chirho),
        Some(("another-app-chirho".to_string(), "view-chirho".to_string()))
    );
    for unconverted_chirho in [
        "/invoke-chirho",
        "/app-chirho/credits-demo-chirho/spend-chirho/extra-chirho",
        "/app-chirho//spend-chirho",
        "/app-chirho/another-app-chirho/",
        "/app-chirho/another-app-chirho/view%2Dchirho",
    ] {
        let uri_chirho: Uri = unconverted_chirho.parse().unwrap();
        assert_eq!(direct_app_route_from_uri_chirho(&uri_chirho), None);
    }
    assert!(relay_only_follower_route_refusal_chirho(
        &Method::GET,
        "/app-chirho/credits-demo-chirho/balance-chirho"
    )
    .is_some());
    // Named POSTs may be transient pure reviews; the owner still refuses every effectful DAG.
    assert!(relay_only_follower_route_refusal_chirho(&Method::POST, named_chirho.path()).is_none());
    assert!(relay_only_follower_route_refusal_chirho(&Method::GET, named_chirho.path()).is_none());
}

#[test]
fn destination_refusal_identity_requires_one_bounded_chirho_name_chirho() {
    assert_eq!(
        refusal_identity_from_body_chirho(b"error: ElectedAuthorityDeposedChirho\n"),
        Some("ElectedAuthorityDeposedChirho".to_string())
    );
    assert_eq!(
        refusal_identity_from_body_chirho(b"error: ElectedAuthorityWrongRootChirho: detail\n"),
        Some("ElectedAuthorityWrongRootChirho".to_string())
    );
    assert_eq!(refusal_identity_from_body_chirho(b"generic failure"), None);
    assert_eq!(
        refusal_identity_from_body_chirho(b"error: not-a-Chirho\n"),
        None
    );
}

#[tokio::test]
async fn transient_destination_classifies_only_typed_engine_refusals_not_payload_text_chirho() {
    let identity_chirho = RelayRefusalIdentityChirho::RelayLocalAuthorityUnavailableChirho;
    let typed_chirho = relay_destination_response_with_http_refusals_chirho(
        relay_named_refusal_response_chirho(
            identity_chirho,
            RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        ),
        true,
    )
    .await
    .into_parts_chirho();
    assert_eq!(typed_chirho.0, RelayOutcomeClassChirho::RelayRefusalChirho);
    assert_eq!(
        typed_chirho.1.as_deref(),
        Some(identity_chirho.as_str_chirho())
    );
    let payload_chirho = format!("error: {}\n", identity_chirho.as_str_chirho());
    let untrusted_chirho = relay_destination_response_with_http_refusals_chirho(
        (StatusCode::SERVICE_UNAVAILABLE, payload_chirho.clone()).into_response(),
        true,
    )
    .await
    .into_parts_chirho();
    assert_eq!(
        untrusted_chirho.0,
        RelayOutcomeClassChirho::ServedResponseChirho
    );
    assert_eq!(untrusted_chirho.2, StatusCode::SERVICE_UNAVAILABLE.as_u16());
    assert_eq!(untrusted_chirho.4, payload_chirho.as_bytes());
}

#[tokio::test]
async fn never_latched_requests_bypass_both_caller_key_and_dispatch_chirho() {
    let platform_chirho = TestPlatformRootChirho::new_chirho("never-latched");
    let root_chirho = tenant_root_chirho(platform_chirho.path_chirho());
    std::fs::create_dir_all(&root_chirho).expect("tenant root");
    let dispatch_chirho =
        StubDispatchChirho::new_chirho(StubDispatchOutcomeChirho::OwnerUnknownChirho);
    let state_chirho = state_with_dispatch_chirho(&root_chirho, dispatch_chirho.clone());
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.append(
        CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("duplicate-one-chirho"),
    );
    headers_chirho.append(
        CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("duplicate-two-chirho"),
    );

    let decision_chirho = dispatch_before_app_selection_chirho(
        &state_chirho,
        &headers_chirho,
        CREDITS_APP_CHIRHO,
        Some(CREDITS_SPEND_ROUTE_CHIRHO),
        &Method::POST,
        &"/app-chirho/credits-demo-chirho/spend-chirho"
            .parse()
            .unwrap(),
        b"never-latched-body-chirho",
        None,
        None,
    )
    .await;

    assert!(matches!(
        decision_chirho,
        ServedWriteBeforeSelectionChirho::ContinueChirho(None)
    ));
    assert_eq!(
        dispatch_chirho.calls_chirho(),
        0,
        "never-latched roots must neither parse the elected caller key nor call a relay port"
    );
}

#[tokio::test]
async fn elected_local_execution_propagates_the_exact_caller_key_chirho() {
    let platform_chirho = TestPlatformRootChirho::new_chirho("local-owner");
    let root_chirho = tenant_root_chirho(platform_chirho.path_chirho());
    std::fs::create_dir_all(&root_chirho).expect("tenant root");
    cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(
        &root_chirho,
        7,
    )
    .expect("geo-latch tenant root");
    let dispatch_chirho =
        StubDispatchChirho::new_chirho(StubDispatchOutcomeChirho::ExecuteLocallyChirho);
    let state_chirho = state_with_dispatch_chirho(&root_chirho, dispatch_chirho.clone());
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("customer-spend-operation-0001-chirho"),
    );
    let uri_chirho: Uri = "/app-chirho/credits-demo-chirho/spend-chirho?bounded=1"
        .parse()
        .unwrap();

    let decision_chirho = dispatch_before_app_selection_chirho(
        &state_chirho,
        &headers_chirho,
        CREDITS_APP_CHIRHO,
        Some(CREDITS_SPEND_ROUTE_CHIRHO),
        &Method::POST,
        &uri_chirho,
        b"spend-body-chirho",
        None,
        None,
    )
    .await;

    let ServedWriteBeforeSelectionChirho::ContinueChirho(Some(caller_operation_chirho)) =
        decision_chirho
    else {
        panic!("local elected owner must continue with the caller key");
    };
    assert_eq!(
        caller_operation_chirho.caller_key_chirho.as_str_chirho(),
        "customer-spend-operation-0001-chirho"
    );
    assert_eq!(
        caller_operation_chirho.operation_chirho.method_chirho(),
        "POST"
    );
    assert_eq!(
        caller_operation_chirho
            .operation_chirho
            .normalized_uri_chirho(),
        uri_chirho.to_string()
    );
    assert_eq!(
        dispatch_chirho.records_chirho(),
        vec![RecordedDispatchChirho {
            caller_key_chirho: "customer-spend-operation-0001-chirho".to_string(),
            method_chirho: "POST".to_string(),
            uri_chirho: uri_chirho.to_string(),
            body_chirho: b"spend-body-chirho".to_vec(),
        }]
    );
}

#[tokio::test]
async fn verified_reentry_skips_a_second_dispatch_and_retains_the_caller_key_chirho() {
    let platform_chirho = TestPlatformRootChirho::new_chirho("reentry");
    let root_chirho = tenant_root_chirho(platform_chirho.path_chirho());
    std::fs::create_dir_all(&root_chirho).expect("tenant root");
    cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(
        &root_chirho,
        7,
    )
    .expect("geo-latch tenant root");
    let dispatch_chirho =
        StubDispatchChirho::new_chirho(StubDispatchOutcomeChirho::OwnerUnknownChirho);
    let state_chirho = state_with_dispatch_chirho(&root_chirho, dispatch_chirho.clone());
    let marker_chirho = RelayedRequestMarkerChirho {
        ingress_chirho: Mutex::new(None),
        caller_operation_chirho: ServedCallerOperationChirho {
            caller_key_chirho: CallerIdempotencyKeyChirho::new_chirho(
                "relayed-spend-operation-0001-chirho",
            )
            .unwrap(),
            operation_chirho: CallerOperationBindingChirho::new_chirho(
                "POST",
                "/app-chirho/credits-demo-chirho/spend-chirho",
            )
            .unwrap(),
            business_body_chirho: None,
        },
    };

    let decision_chirho = dispatch_before_app_selection_chirho(
        &state_chirho,
        &HeaderMap::new(),
        CREDITS_APP_CHIRHO,
        Some(CREDITS_SPEND_ROUTE_CHIRHO),
        &Method::POST,
        &"/app-chirho/credits-demo-chirho/spend-chirho"
            .parse()
            .unwrap(),
        b"relayed-body-chirho",
        Some(&marker_chirho),
        None,
    )
    .await;

    let ServedWriteBeforeSelectionChirho::ContinueChirho(Some(caller_operation_chirho)) =
        decision_chirho
    else {
        panic!("verified reentry must continue with its authenticated caller key");
    };
    assert_eq!(
        caller_operation_chirho.caller_key_chirho.as_str_chirho(),
        "relayed-spend-operation-0001-chirho"
    );
    assert_eq!(
        caller_operation_chirho
            .operation_chirho
            .normalized_uri_chirho(),
        "/app-chirho/credits-demo-chirho/spend-chirho"
    );
    assert_eq!(
        dispatch_chirho.calls_chirho(),
        0,
        "the process-local marker must prevent a second relay decision"
    );
}

#[tokio::test]
async fn elected_refusal_precedes_refs_and_preserves_planted_follower_state_chirho() {
    let platform_chirho = TestPlatformRootChirho::new_chirho("follower-refusal");
    let root_chirho = tenant_root_chirho(platform_chirho.path_chirho());
    std::fs::create_dir_all(&root_chirho).expect("tenant root");
    cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(
        &root_chirho,
        7,
    )
    .expect("geo-latch tenant root");
    std::fs::write(
        root_chirho.join("refs-chirho.json"),
        b"malformed-ref-state-chirho",
    )
    .expect("plant malformed refs");
    std::fs::write(
        root_chirho.join("follower-prestate-chirho"),
        b"nonempty-follower-state-chirho",
    )
    .expect("plant follower state");
    let dispatch_chirho =
        StubDispatchChirho::new_chirho(StubDispatchOutcomeChirho::OwnerUnknownChirho);
    let state_chirho = state_with_dispatch_chirho(&root_chirho, dispatch_chirho.clone());
    let before_chirho = snapshot_files_chirho(&root_chirho);
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("follower-spend-operation-0001-chirho"),
    );

    let response_chirho = app_http_chirho::run_app_http_with_method_for_served_request_chirho(
        &state_chirho,
        Some("127.0.0.1:43111".parse().unwrap()),
        &headers_chirho,
        CREDITS_APP_CHIRHO,
        Some(CREDITS_SPEND_ROUTE_CHIRHO),
        Method::POST,
        b"must-not-reach-follower-refs-chirho".to_vec(),
    )
    .await;
    let (status_chirho, text_chirho) = response_text_chirho(response_chirho).await;

    assert_eq!(status_chirho, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        text_chirho.contains("RelayOwnerUnknownChirho"),
        "{text_chirho}"
    );
    assert!(
        !text_chirho.contains("ref"),
        "the relay refusal was replaced by follower ref processing: {text_chirho}"
    );
    assert_eq!(dispatch_chirho.calls_chirho(), 1);
    assert_eq!(
        snapshot_files_chirho(&root_chirho),
        before_chirho,
        "an elected follower refusal must leave every planted durable byte unchanged"
    );
}

#[tokio::test]
async fn authenticated_follower_refusal_records_no_scoped_token_use_or_other_durable_write_chirho()
{
    let platform_chirho = TestPlatformRootChirho::new_chirho("authenticated-follower-refusal");
    let root_chirho = tenant_root_chirho(platform_chirho.path_chirho());
    std::fs::create_dir_all(&root_chirho).expect("tenant root");
    let headers_chirho = authenticated_credits_headers_chirho(&root_chirho);
    cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(
        &root_chirho,
        7,
    )
    .expect("geo-latch tenant root");
    std::fs::write(
        root_chirho.join("follower-prestate-chirho"),
        b"authenticated-follower-state-chirho",
    )
    .expect("plant follower state");
    let dispatch_chirho =
        StubDispatchChirho::new_chirho(StubDispatchOutcomeChirho::OwnerUnknownChirho);
    let state_chirho = state_with_dispatch_chirho(&root_chirho, dispatch_chirho.clone());
    assert!(
        cairn_chirho::oauth_chirho::load_scoped_token_uses_chirho(&root_chirho)
            .expect("load pre-request token uses")
            .is_empty()
    );
    let before_chirho = snapshot_files_chirho(&root_chirho);

    let response_chirho = app_http_chirho::run_app_http_with_method_for_served_request_chirho(
        &state_chirho,
        Some("127.0.0.1:43112".parse().unwrap()),
        &headers_chirho,
        CREDITS_APP_CHIRHO,
        Some(CREDITS_SPEND_ROUTE_CHIRHO),
        Method::POST,
        b"authenticated-body-never-executes-chirho".to_vec(),
    )
    .await;
    let (status_chirho, text_chirho) = response_text_chirho(response_chirho).await;

    assert_eq!(status_chirho, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        text_chirho.contains("RelayOwnerUnknownChirho"),
        "{text_chirho}"
    );
    assert_eq!(dispatch_chirho.calls_chirho(), 1);
    assert_eq!(
        snapshot_files_chirho(&root_chirho),
        before_chirho,
        "read-only follower authentication must not consume a scoped-token use or mutate any durable byte"
    );
}

#[tokio::test]
async fn elected_post_handler_relays_before_its_route_body_policy_reads_refs_chirho() {
    let platform_chirho = TestPlatformRootChirho::new_chirho("follower-post-handler");
    let root_chirho = tenant_root_chirho(platform_chirho.path_chirho());
    std::fs::create_dir_all(&root_chirho).expect("tenant root");
    cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(
        &root_chirho,
        7,
    )
    .expect("geo-latch tenant root");
    std::fs::write(
        root_chirho.join("refs-chirho.json"),
        b"malformed-ref-state-chirho",
    )
    .expect("plant malformed refs");
    std::fs::write(
        root_chirho.join("follower-prestate-chirho"),
        b"nonempty-follower-state-chirho",
    )
    .expect("plant follower state");
    let dispatch_chirho =
        StubDispatchChirho::new_chirho(StubDispatchOutcomeChirho::OwnerUnknownChirho);
    let state_chirho = state_with_dispatch_chirho(&root_chirho, dispatch_chirho.clone());
    let before_chirho = snapshot_files_chirho(&root_chirho);
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("follower-post-handler-operation-0001-chirho"),
    );
    let request_chirho = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/app-chirho/credits-demo-chirho/spend-chirho")
        .body(axum::body::Body::from("must-not-reach-route-policy-chirho"))
        .expect("bounded POST request");

    let response_chirho = app_http_chirho::app_route_post_request_chirho(
        axum::extract::State(state_chirho),
        None,
        headers_chirho,
        axum::extract::Path((
            CREDITS_APP_CHIRHO.to_string(),
            CREDITS_SPEND_ROUTE_CHIRHO.to_string(),
        )),
        request_chirho,
    )
    .await;
    let (status_chirho, text_chirho) = response_text_chirho(response_chirho).await;

    assert_eq!(status_chirho, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        text_chirho.contains("RelayOwnerUnknownChirho"),
        "{text_chirho}"
    );
    assert!(
        !text_chirho.contains("ref") && !text_chirho.contains("policy"),
        "the relay refusal was replaced by a pre-relay route-policy read: {text_chirho}"
    );
    assert_eq!(dispatch_chirho.calls_chirho(), 1);
    assert_eq!(
        snapshot_files_chirho(&root_chirho),
        before_chirho,
        "the actual follower POST handler must leave every planted durable byte unchanged"
    );
}

#[tokio::test]
async fn elected_missing_key_and_unconverted_route_refuse_by_distinct_names_chirho() {
    let platform_chirho = TestPlatformRootChirho::new_chirho("named-refusals");
    let root_chirho = tenant_root_chirho(platform_chirho.path_chirho());
    std::fs::create_dir_all(&root_chirho).expect("tenant root");
    cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(
        &root_chirho,
        7,
    )
    .expect("geo-latch tenant root");
    let dispatch_chirho =
        StubDispatchChirho::new_chirho(StubDispatchOutcomeChirho::ExecuteLocallyChirho);
    let state_chirho = state_with_dispatch_chirho(&root_chirho, dispatch_chirho.clone());

    let missing_key_chirho = dispatch_before_app_selection_chirho(
        &state_chirho,
        &HeaderMap::new(),
        CREDITS_APP_CHIRHO,
        Some(CREDITS_SPEND_ROUTE_CHIRHO),
        &Method::POST,
        &"/app-chirho/credits-demo-chirho/spend-chirho"
            .parse()
            .unwrap(),
        b"",
        None,
        None,
    )
    .await;
    let ServedWriteBeforeSelectionChirho::RespondChirho(missing_key_chirho) = missing_key_chirho
    else {
        panic!("elected spend without a caller key must refuse");
    };
    let (_, missing_text_chirho) = response_text_chirho(missing_key_chirho).await;
    assert!(
        missing_text_chirho.contains("RelayCallerKeyInvalidChirho"),
        "{missing_text_chirho}"
    );
    assert!(
        !missing_text_chirho.contains("RelayMutationFamilyUnconvertedChirho"),
        "{missing_text_chirho}"
    );

    let mut duplicate_headers_chirho = HeaderMap::new();
    duplicate_headers_chirho.append(
        CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("duplicate-operation-one-chirho"),
    );
    duplicate_headers_chirho.append(
        CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("duplicate-operation-two-chirho"),
    );
    let duplicate_key_chirho = dispatch_before_app_selection_chirho(
        &state_chirho,
        &duplicate_headers_chirho,
        CREDITS_APP_CHIRHO,
        Some(CREDITS_SPEND_ROUTE_CHIRHO),
        &Method::POST,
        &"/app-chirho/credits-demo-chirho/spend-chirho"
            .parse()
            .unwrap(),
        b"",
        None,
        None,
    )
    .await;
    let ServedWriteBeforeSelectionChirho::RespondChirho(duplicate_key_chirho) =
        duplicate_key_chirho
    else {
        panic!("elected spend with duplicate caller keys must refuse");
    };
    let (_, duplicate_text_chirho) = response_text_chirho(duplicate_key_chirho).await;
    assert!(
        duplicate_text_chirho.contains("RelayCallerKeyInvalidChirho"),
        "{duplicate_text_chirho}"
    );
    assert!(
        !duplicate_text_chirho.contains("RelayMutationFamilyUnconvertedChirho"),
        "{duplicate_text_chirho}"
    );

    let unconverted_chirho = dispatch_before_app_selection_chirho(
        &state_chirho,
        &HeaderMap::new(),
        CREDITS_APP_CHIRHO,
        Some("balance-chirho"),
        &Method::GET,
        &"/app-chirho/credits-demo-chirho/balance-chirho"
            .parse()
            .unwrap(),
        b"",
        None,
        None,
    )
    .await;
    let ServedWriteBeforeSelectionChirho::RespondChirho(unconverted_chirho) = unconverted_chirho
    else {
        panic!("unconverted elected route must refuse");
    };
    let (_, unconverted_text_chirho) = response_text_chirho(unconverted_chirho).await;
    assert!(
        unconverted_text_chirho.contains("RelayMutationFamilyUnconvertedChirho"),
        "{unconverted_text_chirho}"
    );
    assert!(
        !unconverted_text_chirho.contains("RelayCallerKeyInvalidChirho"),
        "{unconverted_text_chirho}"
    );
    assert_eq!(dispatch_chirho.calls_chirho(), 0);
}

// The browser caller-key carrier through the relay (gpt #28889): the run and the relay see only the business
// body, re-entry never asks for the removed field, and every malformed key refuses before any dispatch.

const FORM_SPEND_BODY_CHIRHO: &[u8] =
    b"item_chirho=render-run-chirho&idempotency_key_chirho=form-spend-key-0001-chirho&concurrency_token_chirho=ab";
const STRIPPED_SPEND_BODY_CHIRHO: &[u8] =
    b"item_chirho=render-run-chirho&concurrency_token_chirho=ab";

fn browser_form_headers_chirho() -> HeaderMap {
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers_chirho
}

fn elected_spend_state_chirho(
    label_chirho: &str,
    outcome_chirho: StubDispatchOutcomeChirho,
) -> (
    TestPlatformRootChirho,
    AppStateChirho,
    Arc<StubDispatchChirho>,
) {
    let platform_chirho = TestPlatformRootChirho::new_chirho(label_chirho);
    let root_chirho = tenant_root_chirho(platform_chirho.path_chirho());
    std::fs::create_dir_all(&root_chirho).expect("tenant root");
    cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(
        &root_chirho,
        7,
    )
    .expect("geo-latch tenant root");
    let dispatch_chirho = StubDispatchChirho::new_chirho(outcome_chirho);
    let state_chirho = state_with_dispatch_chirho(&root_chirho, dispatch_chirho.clone());
    (platform_chirho, state_chirho, dispatch_chirho)
}

async fn spend_decision_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
    body_chirho: &[u8],
    reentry_chirho: Option<&RelayedRequestMarkerChirho>,
) -> ServedWriteBeforeSelectionChirho {
    dispatch_before_app_selection_chirho(
        state_chirho,
        headers_chirho,
        CREDITS_APP_CHIRHO,
        Some(CREDITS_SPEND_ROUTE_CHIRHO),
        &Method::POST,
        &CREDITS_SPEND_PATH_CHIRHO.parse().unwrap(),
        body_chirho,
        reentry_chirho,
        None,
    )
    .await
}

fn location_chirho(response_chirho: &Response) -> &str {
    response_chirho
        .headers()
        .get(axum::http::header::LOCATION)
        .expect("a browser refusal names where to go")
        .to_str()
        .expect("ASCII location")
}

#[tokio::test]
async fn a_local_owner_form_runs_and_dispatches_only_the_stripped_body_chirho() {
    let (_platform_chirho, state_chirho, dispatch_chirho) = elected_spend_state_chirho(
        "form-local",
        StubDispatchOutcomeChirho::ExecuteLocallyChirho,
    );
    let ServedWriteBeforeSelectionChirho::ContinueChirho(Some(caller_operation_chirho)) =
        spend_decision_chirho(
            &state_chirho,
            &browser_form_headers_chirho(),
            FORM_SPEND_BODY_CHIRHO,
            None,
        )
        .await
    else {
        panic!("a form's key on a local owner continues to the run");
    };
    let (caller_key_chirho, _operation_chirho, business_body_chirho) =
        caller_operation_chirho.into_parts_chirho();
    assert_eq!(
        caller_key_chirho.as_str_chirho(),
        "form-spend-key-0001-chirho"
    );
    assert_eq!(
        business_body_chirho.as_deref(),
        Some(STRIPPED_SPEND_BODY_CHIRHO),
        "Continue carries the stripped body to the run; dropping it would run the raw form"
    );
    let records_chirho = dispatch_chirho.records_chirho();
    assert_eq!(records_chirho.len(), 1);
    assert_eq!(
        records_chirho[0].caller_key_chirho,
        "form-spend-key-0001-chirho"
    );
    assert_eq!(records_chirho[0].body_chirho, STRIPPED_SPEND_BODY_CHIRHO);
}

#[tokio::test]
async fn a_forwarded_form_sends_only_the_stripped_body_and_its_refusal_is_browser_shaped_chirho() {
    let (_platform_chirho, state_chirho, dispatch_chirho) = elected_spend_state_chirho(
        "form-forward",
        StubDispatchOutcomeChirho::OwnerUnknownChirho,
    );
    let ServedWriteBeforeSelectionChirho::RespondChirho(browser_chirho) = spend_decision_chirho(
        &state_chirho,
        &browser_form_headers_chirho(),
        FORM_SPEND_BODY_CHIRHO,
        None,
    )
    .await
    else {
        panic!("no relay owner refuses");
    };
    assert_eq!(
        dispatch_chirho.records_chirho()[0].body_chirho,
        STRIPPED_SPEND_BODY_CHIRHO,
        "the relay forwards the business body, never the carrier field"
    );
    assert_eq!(browser_chirho.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location_chirho(&browser_chirho),
        "/app-chirho/credits-demo-chirho/#refusal-write-unavailable-chirho"
    );
    // The same refusal to a script that sends the header keeps the relay's status and identity.
    let mut scripted_chirho = browser_form_headers_chirho();
    scripted_chirho.insert(
        CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("drill-spend-key-0001-chirho"),
    );
    let ServedWriteBeforeSelectionChirho::RespondChirho(plain_chirho) = spend_decision_chirho(
        &state_chirho,
        &scripted_chirho,
        STRIPPED_SPEND_BODY_CHIRHO,
        None,
    )
    .await
    else {
        panic!("no relay owner refuses");
    };
    let (plain_status_chirho, plain_body_chirho) = response_text_chirho(plain_chirho).await;
    assert_eq!(plain_status_chirho, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(plain_body_chirho, "error: RelayOwnerUnknownChirho\n");
    assert_eq!(
        dispatch_chirho.records_chirho()[1].body_chirho,
        STRIPPED_SPEND_BODY_CHIRHO,
        "a header-only form body is forwarded exactly as sent"
    );
}

#[tokio::test]
async fn owner_reentry_with_form_headers_never_asks_for_the_removed_field_chirho() {
    let (_platform_chirho, state_chirho, dispatch_chirho) = elected_spend_state_chirho(
        "form-reentry",
        StubDispatchOutcomeChirho::OwnerUnknownChirho,
    );
    let marker_chirho = RelayedRequestMarkerChirho {
        ingress_chirho: Mutex::new(None),
        caller_operation_chirho: ServedCallerOperationChirho {
            caller_key_chirho: CallerIdempotencyKeyChirho::new_chirho("form-spend-key-0001-chirho")
                .unwrap(),
            operation_chirho: CallerOperationBindingChirho::new_chirho(
                "POST",
                CREDITS_SPEND_PATH_CHIRHO,
            )
            .unwrap(),
            business_body_chirho: None,
        },
    };
    let ServedWriteBeforeSelectionChirho::ContinueChirho(Some(caller_operation_chirho)) =
        spend_decision_chirho(
            &state_chirho,
            &browser_form_headers_chirho(),
            STRIPPED_SPEND_BODY_CHIRHO,
            Some(&marker_chirho),
        )
        .await
    else {
        panic!("re-entry continues on its verified marker, with no field in the body");
    };
    let (caller_key_chirho, _operation_chirho, business_body_chirho) =
        caller_operation_chirho.into_parts_chirho();
    assert_eq!(
        caller_key_chirho.as_str_chirho(),
        "form-spend-key-0001-chirho"
    );
    assert_eq!(
        business_body_chirho, None,
        "re-entry runs the stripped body it was sent"
    );
    assert_eq!(dispatch_chirho.calls_chirho(), 0);
}

#[tokio::test]
async fn conflicting_duplicate_or_multipart_form_keys_refuse_before_any_dispatch_chirho() {
    let (_platform_chirho, state_chirho, dispatch_chirho) = elected_spend_state_chirho(
        "form-refusals",
        StubDispatchOutcomeChirho::ExecuteLocallyChirho,
    );
    let ServedWriteBeforeSelectionChirho::RespondChirho(duplicate_chirho) = spend_decision_chirho(
        &state_chirho,
        &browser_form_headers_chirho(),
        b"idempotency_key_chirho=same-key-chirho&idempotency_key_chirho=same-key-chirho",
        None,
    )
    .await
    else {
        panic!("a doubled field refuses");
    };
    assert_eq!(duplicate_chirho.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location_chirho(&duplicate_chirho),
        "/app-chirho/credits-demo-chirho/#refusal-caller-key-invalid-chirho"
    );
    let mut conflicting_chirho = browser_form_headers_chirho();
    conflicting_chirho.insert(
        CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("header-key-chirho"),
    );
    let ServedWriteBeforeSelectionChirho::RespondChirho(conflict_chirho) = spend_decision_chirho(
        &state_chirho,
        &conflicting_chirho,
        b"idempotency_key_chirho=field-key-chirho&item_chirho=x",
        None,
    )
    .await
    else {
        panic!("a header that disagrees with the field refuses");
    };
    let (conflict_status_chirho, conflict_body_chirho) =
        response_text_chirho(conflict_chirho).await;
    assert_eq!(conflict_status_chirho, StatusCode::BAD_REQUEST);
    assert_eq!(conflict_body_chirho, "error: RelayCallerKeyInvalidChirho\n");
    let mut multipart_chirho = HeaderMap::new();
    multipart_chirho.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("multipart/form-data; boundary=x-chirho"),
    );
    let ServedWriteBeforeSelectionChirho::RespondChirho(multipart_response_chirho) =
        spend_decision_chirho(
            &state_chirho,
            &multipart_chirho,
            b"--x-chirho\r\ncontent-disposition: form-data; name=\"idempotency_key_chirho\"\r\n\r\nk\r\n--x-chirho--\r\n",
            None,
        )
        .await
    else {
        panic!("multipart is not carried yet and refuses");
    };
    assert_eq!(multipart_response_chirho.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        dispatch_chirho.calls_chirho(),
        0,
        "every malformed key refuses before the relay is asked"
    );
}

fn placeholder_page_chirho() -> Response {
    let mut response_chirho = Response::new(axum::body::Body::from(format!(
        "<form>{}</form>",
        caller_key_carrier_chirho::FORM_CALLER_KEY_PLACEHOLDER_CHIRHO
    )));
    response_chirho.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response_chirho
}

#[tokio::test]
async fn keys_go_into_a_browser_answer_but_never_into_a_relayed_reentry_or_a_local_root_chirho() {
    let placeholder_bytes_chirho =
        caller_key_carrier_chirho::FORM_CALLER_KEY_PLACEHOLDER_CHIRHO.as_bytes();
    let (_elected_platform_chirho, elected_state_chirho, _elected_dispatch_chirho) =
        elected_spend_state_chirho(
            "issue-at-the-edge",
            StubDispatchOutcomeChirho::ExecuteLocallyChirho,
        );
    // The node answering the browser fills the page and keeps it out of every cache.
    let browser_chirho = app_http_chirho::finish_answer_for_browser_chirho(
        &elected_state_chirho,
        CREDITS_APP_CHIRHO,
        false,
        placeholder_page_chirho(),
    )
    .await;
    assert_eq!(
        browser_chirho
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .unwrap(),
        "private, no-store"
    );
    let browser_text_chirho = response_text_chirho(browser_chirho).await.1;
    assert!(!browser_text_chirho
        .contains(caller_key_carrier_chirho::FORM_CALLER_KEY_PLACEHOLDER_CHIRHO));
    // The owner answering a relayed re-entry leaves its signed answer exactly as produced.
    let relayed_chirho = app_http_chirho::finish_answer_for_browser_chirho(
        &elected_state_chirho,
        CREDITS_APP_CHIRHO,
        true,
        placeholder_page_chirho(),
    )
    .await;
    assert!(relayed_chirho
        .headers()
        .get(axum::http::header::CACHE_CONTROL)
        .is_none());
    let relayed_text_chirho = response_text_chirho(relayed_chirho).await.1;
    assert_eq!(
        relayed_text_chirho.as_bytes(),
        format!(
            "<form>{}</form>",
            caller_key_carrier_chirho::FORM_CALLER_KEY_PLACEHOLDER_CHIRHO
        )
        .as_bytes(),
        "a relayed re-entry keeps its empty placeholder, so the source issues fresh keys"
    );
    // A never-latched (local) root keeps the placeholder empty: no key is needed there (gpt #28746).
    let local_platform_chirho = TestPlatformRootChirho::new_chirho("issue-local-root");
    let local_root_chirho = tenant_root_chirho(local_platform_chirho.path_chirho());
    std::fs::create_dir_all(&local_root_chirho).expect("tenant root");
    let local_state_chirho = state_with_dispatch_chirho(
        &local_root_chirho,
        StubDispatchChirho::new_chirho(StubDispatchOutcomeChirho::ExecuteLocallyChirho),
    );
    let local_chirho = app_http_chirho::finish_answer_for_browser_chirho(
        &local_state_chirho,
        CREDITS_APP_CHIRHO,
        false,
        placeholder_page_chirho(),
    )
    .await;
    let local_text_chirho = response_text_chirho(local_chirho).await.1;
    assert!(
        local_text_chirho
            .as_bytes()
            .windows(placeholder_bytes_chirho.len())
            .any(|window_chirho| window_chirho == placeholder_bytes_chirho),
        "a local root issues no key into an ordinary app's page"
    );
}
