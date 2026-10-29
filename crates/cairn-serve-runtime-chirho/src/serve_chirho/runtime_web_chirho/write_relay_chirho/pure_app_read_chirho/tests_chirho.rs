// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::serve_chirho;
use crate::serve_chirho::write_relay_chirho as relay_web_chirho;
use axum::body::to_bytes;
use axum::extract::{OriginalUri, Path as AxPath, State};
use axum::http::header::{COOKIE, RETRY_AFTER};
use cairn_chirho::model_chirho::{
    CapabilityChirho, DagChirho, HashChirho, NodeDefChirho, PortChirho,
};
use cairn_write_relay_chirho::{
    decode_and_verify_served_write_relay_request_chirho,
    decode_and_verify_served_write_relay_response_chirho,
    relay_tenant_consistency_group_digest_chirho, PreparedServedWriteRelayRequestV1Chirho,
    PreparedServedWriteRelayResponseV1Chirho, RelayContractErrorChirho,
    RelayDestinationExecutionPortChirho, RelayDestinationResponseChirho, RelayIngressScopeChirho,
    RelayRosterChirho, RelayTransportFailureChirho, ServedLocalReadAuthorityPortChirho,
    ServedLocalReadAuthorityWitnessChirho, ServedWriteDispatchFutureChirho,
    ServedWriteDispatchInputChirho, ServedWriteDispatchOutcomeChirho,
    ServedWriteDispatchPortChirho, ServedWriteRelayFailureChirho,
    ServedWriteRelayRequestInputChirho, ServedWriteRelayResponseInputChirho,
};
use ed25519_dalek::{Signer as _, SigningKey};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

const APP_CHIRHO: &str = "pure-read-fixture-chirho";
const ROUTE_CHIRHO: &str = "view-chirho";
const TENANT_CHIRHO: &str = "pure-read-tenant-chirho";
const TERM_CHIRHO: u64 = 7;
static FIXTURE_SEQUENCE_CHIRHO: AtomicUsize = AtomicUsize::new(0);

struct FixtureChirho {
    platform_chirho: PathBuf,
    root_chirho: PathBuf,
    owner_chirho: String,
    dag_chirho: HashChirho,
}

impl FixtureChirho {
    fn new_chirho(capabilities_chirho: Vec<CapabilityChirho>) -> Self {
        let stamp_chirho = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("fixture clock")
            .as_nanos();
        let platform_chirho = std::env::temp_dir().join(format!(
            "pure-app-read-{}-{stamp_chirho}-{}-chirho",
            std::process::id(),
            FIXTURE_SEQUENCE_CHIRHO.fetch_add(1, Ordering::SeqCst)
        ));
        let root_chirho = cairn_chirho::tenant_chirho::root_for_tenant_chirho(
            &platform_chirho,
            &cairn_chirho::tenant_chirho::TenantIdChirho::TenantChirho(TENANT_CHIRHO.to_string()),
        )
        .expect("tenant root");
        let owner_chirho = cairn_chirho::identity_chirho::register_identity_chirho(
            &root_chirho,
            cairn_chirho::identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .expect("fixture owner")
        .principal_chirho;
        let wasm_chirho = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples-chirho/upcase-chirho.wat"
        ));
        let wasm_hash_chirho =
            cairn_chirho::cas_chirho::add_chirho(&root_chirho, wasm_chirho.as_bytes())
                .expect("fixture WASM");
        let node_chirho = cairn_chirho::store_chirho::put_object_chirho(
            &root_chirho,
            &NodeDefChirho {
                name_chirho: "pure_read_fixture_chirho".to_string(),
                impl_wasm_chirho: wasm_hash_chirho,
                entry_chirho: "upcase_chirho".to_string(),
                inputs_chirho: vec![PortChirho {
                    name_chirho: "in_chirho".to_string(),
                    schema_chirho: HashChirho("bytes-chirho".to_string()),
                }],
                outputs_chirho: vec![PortChirho {
                    name_chirho: "out_chirho".to_string(),
                    schema_chirho: HashChirho("bytes-chirho".to_string()),
                }],
                capabilities_chirho,
                fuel_limit_chirho: 1_000_000,
                ..Default::default()
            },
        )
        .expect("fixture node");
        let dag_chirho = cairn_chirho::store_chirho::put_object_chirho(
            &root_chirho,
            &DagChirho {
                nodes_chirho: vec![node_chirho],
                edges_chirho: Vec::new(),
            },
        )
        .expect("fixture DAG");
        app_chirho::deploy_app_chirho(&root_chirho, APP_CHIRHO, dag_chirho.clone(), &owner_chirho)
            .expect("fixture app");
        app_chirho::deploy_app_route_chirho(
            &root_chirho,
            APP_CHIRHO,
            ROUTE_CHIRHO,
            dag_chirho.clone(),
            &owner_chirho,
        )
        .expect("named fixture route");
        app_chirho::set_app_input_policy_chirho(
            &root_chirho,
            APP_CHIRHO,
            None,
            &owner_chirho,
            app_chirho::AppInputModeChirho::PlainChirho,
        )
        .expect("plain input policy");
        app_chirho::set_app_input_policy_chirho(
            &root_chirho,
            APP_CHIRHO,
            Some(ROUTE_CHIRHO),
            &owner_chirho,
            app_chirho::AppInputModeChirho::PlainChirho,
        )
        .expect("signed named-route input policy");
        app_chirho::set_app_params_chirho(
            &root_chirho,
            APP_CHIRHO,
            Some(ROUTE_CHIRHO),
            &owner_chirho,
            &serde_json::json!({"message_chirho": "hello from wasm"}),
            true,
        )
        .expect("signed app params");
        let planted_chirho = root_chirho.join("snapshot-control-chirho/nested-chirho");
        std::fs::create_dir_all(&planted_chirho).expect("nested snapshot control");
        std::fs::write(
            planted_chirho.join("sentinel-chirho"),
            b"\0durable-control-chirho\xff",
        )
        .expect("binary snapshot control");
        Self {
            platform_chirho,
            root_chirho,
            owner_chirho,
            dag_chirho,
        }
    }

    fn latch_chirho(&self) {
        cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(
            &self.root_chirho,
            TERM_CHIRHO,
        )
        .expect("elected root latch");
    }

    fn require_cookie_chirho(&self) {
        app_chirho::set_app_request_access_policy_chirho(
            &self.root_chirho,
            APP_CHIRHO,
            &self.owner_chirho,
            self.dag_chirho.clone(),
            app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho,
        )
        .expect("authenticated fixture");
    }

    fn cookie_chirho(&self) -> (HeaderValue, String) {
        let user_chirho = cairn_chirho::identity_chirho::register_identity_chirho(
            &self.root_chirho,
            cairn_chirho::identity_chirho::PrincipalKindChirho::UserChirho,
        )
        .expect("cookie user");
        let login_chirho = cairn_chirho::identity_chirho::login_identity_chirho(
            &self.root_chirho,
            &user_chirho.principal_chirho,
        )
        .expect("cookie session");
        let cookie_chirho = format!(
            "cairn_session_chirho={}:{}",
            user_chirho.principal_chirho, login_chirho.token_chirho
        )
        .parse()
        .expect("cookie header");
        (cookie_chirho, user_chirho.principal_chirho)
    }

    fn snapshot_chirho(&self) -> BTreeMap<PathBuf, SnapshotEntryChirho> {
        let snapshot_chirho = snapshot_chirho(&self.platform_chirho);
        assert!(snapshot_chirho.keys().any(|path_chirho| path_chirho
            .ends_with("snapshot-control-chirho/nested-chirho/sentinel-chirho")));
        snapshot_chirho
    }
}

impl Drop for FixtureChirho {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.platform_chirho);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SnapshotEntryChirho {
    DirectoryChirho,
    FileChirho(Vec<u8>),
    SymlinkChirho(PathBuf),
}

fn snapshot_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, SnapshotEntryChirho> {
    fn walk_chirho(
        root_chirho: &Path,
        path_chirho: &Path,
        entries_chirho: &mut BTreeMap<PathBuf, SnapshotEntryChirho>,
    ) {
        let metadata_chirho = std::fs::symlink_metadata(path_chirho).expect("snapshot metadata");
        let key_chirho = path_chirho
            .strip_prefix(root_chirho)
            .expect("snapshot relative path")
            .to_path_buf();
        let entry_chirho = if metadata_chirho.file_type().is_symlink() {
            SnapshotEntryChirho::SymlinkChirho(
                std::fs::read_link(path_chirho).expect("snapshot link"),
            )
        } else if metadata_chirho.is_dir() {
            SnapshotEntryChirho::DirectoryChirho
        } else {
            assert!(metadata_chirho.is_file(), "unexpected fixture file type");
            SnapshotEntryChirho::FileChirho(std::fs::read(path_chirho).expect("snapshot bytes"))
        };
        entries_chirho.insert(key_chirho, entry_chirho);
        if metadata_chirho.is_dir() {
            for child_chirho in std::fs::read_dir(path_chirho).expect("snapshot directory") {
                walk_chirho(
                    root_chirho,
                    &child_chirho.expect("snapshot child").path(),
                    entries_chirho,
                );
            }
        }
    }
    let mut entries_chirho = BTreeMap::new();
    walk_chirho(root_chirho, root_chirho, &mut entries_chirho);
    entries_chirho
}

struct AuthorityChirho {
    refuse_at_chirho: Option<usize>,
    begin_chirho: AtomicUsize,
    confirms_chirho: AtomicUsize,
}

impl AuthorityChirho {
    fn new_chirho(refuse_at_chirho: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            refuse_at_chirho,
            begin_chirho: AtomicUsize::new(0),
            confirms_chirho: AtomicUsize::new(0),
        })
    }
}

impl ServedLocalReadAuthorityPortChirho for AuthorityChirho {
    fn begin_local_read_chirho(
        &self,
    ) -> Result<ServedLocalReadAuthorityWitnessChirho, ServedWriteRelayFailureChirho> {
        self.begin_chirho.fetch_add(1, Ordering::SeqCst);
        if self.refuse_at_chirho == Some(0) {
            return Err(RelayContractErrorChirho::local_authority_unavailable_chirho().into());
        }
        Ok(ServedLocalReadAuthorityWitnessChirho::new_chirho(
            "owner-node-chirho".to_string(),
            TERM_CHIRHO,
        ))
    }

    fn confirm_local_read_chirho(
        &self,
        witness_chirho: &ServedLocalReadAuthorityWitnessChirho,
    ) -> Result<(), ServedWriteRelayFailureChirho> {
        assert_eq!(witness_chirho.local_node_id_chirho(), "owner-node-chirho");
        assert_eq!(witness_chirho.term_chirho(), TERM_CHIRHO);
        let call_chirho = self.confirms_chirho.fetch_add(1, Ordering::SeqCst) + 1;
        if self.refuse_at_chirho == Some(call_chirho) {
            Err(RelayContractErrorChirho::owner_term_changed_chirho().into())
        } else {
            Ok(())
        }
    }
}

struct LocalDispatchChirho {
    calls_chirho: AtomicUsize,
    scope_chirho: RelayIngressScopeChirho,
}

impl LocalDispatchChirho {
    fn new_chirho() -> Arc<Self> {
        Arc::new(Self {
            calls_chirho: AtomicUsize::new(0),
            scope_chirho: ingress_scope_chirho(true),
        })
    }
}

impl ServedWriteDispatchPortChirho for LocalDispatchChirho {
    fn ingress_scope_chirho(&self) -> Option<RelayIngressScopeChirho> {
        Some(self.scope_chirho.clone())
    }

    fn dispatch_chirho<'a>(
        &'a self,
        input_chirho: ServedWriteDispatchInputChirho,
    ) -> ServedWriteDispatchFutureChirho<'a> {
        Box::pin(async move {
            self.calls_chirho.fetch_add(1, Ordering::SeqCst);
            assert_eq!(input_chirho.method_chirho, "GET");
            assert!(input_chirho.body_chirho.is_empty());
            Ok(ServedWriteDispatchOutcomeChirho::ExecuteLocallyChirho)
        })
    }
}

fn state_chirho(
    fixture_chirho: &FixtureChirho,
    dispatch_chirho: Arc<dyn ServedWriteDispatchPortChirho>,
    authority_chirho: Arc<AuthorityChirho>,
    limits_chirho: serve_chirho::ServedRequestAbuseLimitsChirho,
) -> AppStateChirho {
    try_state_chirho(
        fixture_chirho,
        dispatch_chirho,
        authority_chirho,
        limits_chirho,
    )
    .expect("pure app state")
}

fn try_state_chirho(
    fixture_chirho: &FixtureChirho,
    dispatch_chirho: Arc<dyn ServedWriteDispatchPortChirho>,
    authority_chirho: Arc<AuthorityChirho>,
    limits_chirho: serve_chirho::ServedRequestAbuseLimitsChirho,
) -> anyhow::Result<AppStateChirho> {
    serve_chirho::app_state_for_runtime_root_with_effect_runtime_chirho(
        &fixture_chirho.root_chirho,
        serve_chirho::RuntimeAppStateOptionsChirho {
            inflight_limit_chirho: 8,
            auth_tokens_chirho: serve_chirho::ServeAuthTokensChirho::default(),
            domain_routing_enabled_chirho: false,
            served_request_limits_chirho: limits_chirho,
            projection_read_chirho: None,
            postgres_effect_chirho: None,
            llm_served_chirho: None,
            write_dispatch_chirho: Some(dispatch_chirho),
            local_read_authority_chirho: Some(authority_chirho),
            write_destination_slot_chirho: None,
        },
    )
}

fn headers_chirho() -> HeaderMap {
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        relay_web_chirho::CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("pure-read-operation-0001-chirho"),
    );
    headers_chirho
}

#[derive(Debug)]
struct ResponsePartsChirho {
    status_chirho: StatusCode,
    headers_chirho: HeaderMap,
    body_chirho: Vec<u8>,
}

async fn get_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: HeaderMap,
) -> ResponsePartsChirho {
    let response_chirho = app_http_chirho::app_route_get_chirho(
        State(state_chirho.clone()),
        None,
        headers_chirho,
        AxPath((APP_CHIRHO.to_string(), ROUTE_CHIRHO.to_string())),
        OriginalUri(
            format!("/app-chirho/{APP_CHIRHO}/{ROUTE_CHIRHO}?probe_chirho=kept")
                .parse()
                .expect("named GET URI"),
        ),
    )
    .await;
    response_parts_chirho(response_chirho).await
}

async fn response_parts_chirho(response_chirho: Response) -> ResponsePartsChirho {
    let status_chirho = response_chirho.status();
    let headers_chirho = response_chirho.headers().clone();
    let body_chirho = to_bytes(response_chirho.into_body(), 2 * 1024 * 1024)
        .await
        .expect("bounded response")
        .to_vec();
    assert_eq!(
        headers_chirho.get(CACHE_CONTROL).expect("cache fence"),
        "private, no-store"
    );
    ResponsePartsChirho {
        status_chirho,
        headers_chirho,
        body_chirho,
    }
}

fn assert_wasm_output_chirho(response_chirho: &ResponsePartsChirho, user_chirho: Option<&str>) {
    assert_eq!(response_chirho.status_chirho, StatusCode::OK);
    let output_chirho: serde_json::Value = serde_json::from_slice(&response_chirho.body_chirho)
        .expect("actual WASM uppercase JSON output");
    let mut expected_chirho =
        serde_json::json!({"APP_PARAMS_CHIRHO": {"MESSAGE_CHIRHO": "HELLO FROM WASM"}});
    if let Some(user_chirho) = user_chirho {
        expected_chirho["USER_PRINCIPAL_CHIRHO"] =
            serde_json::Value::String(user_chirho.to_ascii_uppercase());
    }
    assert_eq!(
        output_chirho, expected_chirho,
        "GET must execute WASM on the verified envelope"
    );
}

fn hex_chirho(bytes_chirho: &[u8]) -> String {
    bytes_chirho
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}

#[derive(Clone, Copy)]
enum TransportModeChirho {
    DeliverChirho,
    UnknownChirho,
    AmbiguousChirho,
    LoseResponseChirho,
}

// This transport crosses both signed wire boundaries and uses the production destination slot.
// It deliberately does not replace the destination with a canned HTTP response.
struct SignedTransportChirho {
    destination_chirho: relay_web_chirho::ServedWriteRelayDestinationSlotChirho,
    mode_chirho: TransportModeChirho,
    calls_chirho: AtomicUsize,
    destination_calls_chirho: AtomicUsize,
    records_chirho: Mutex<Vec<(String, String, Vec<u8>)>>,
    origin_seed_chirho: u8,
    roster_seeds_chirho: Vec<u8>,
}

impl SignedTransportChirho {
    fn new_chirho(
        destination_chirho: relay_web_chirho::ServedWriteRelayDestinationSlotChirho,
        mode_chirho: TransportModeChirho,
    ) -> Arc<Self> {
        Self::with_origins_chirho(destination_chirho, mode_chirho, 0x31, vec![0x31, 0x52])
    }

    fn with_origins_chirho(
        destination_chirho: relay_web_chirho::ServedWriteRelayDestinationSlotChirho,
        mode_chirho: TransportModeChirho,
        origin_seed_chirho: u8,
        roster_seeds_chirho: Vec<u8>,
    ) -> Arc<Self> {
        Arc::new(Self {
            destination_chirho,
            mode_chirho,
            calls_chirho: AtomicUsize::new(0),
            destination_calls_chirho: AtomicUsize::new(0),
            records_chirho: Mutex::new(Vec::new()),
            origin_seed_chirho,
            roster_seeds_chirho,
        })
    }
}

impl ServedWriteDispatchPortChirho for SignedTransportChirho {
    fn ingress_scope_chirho(&self) -> Option<RelayIngressScopeChirho> {
        Some(scope_for_seeds_chirho(
            self.origin_seed_chirho,
            &self.roster_seeds_chirho,
        ))
    }

    fn dispatch_chirho<'a>(
        &'a self,
        input_chirho: ServedWriteDispatchInputChirho,
    ) -> ServedWriteDispatchFutureChirho<'a> {
        Box::pin(async move {
            self.calls_chirho.fetch_add(1, Ordering::SeqCst);
            self.records_chirho
                .lock()
                .expect("transport records")
                .push((
                    input_chirho.method_chirho.clone(),
                    input_chirho.uri_chirho.clone(),
                    input_chirho.body_chirho.clone(),
                ));
            match self.mode_chirho {
                TransportModeChirho::UnknownChirho => {
                    return Err(RelayContractErrorChirho::owner_unknown_chirho().into())
                }
                TransportModeChirho::AmbiguousChirho => {
                    return Err(
                        RelayTransportFailureChirho::outcome_ambiguous_after_transmission_chirho()
                            .into(),
                    )
                }
                _ => {}
            }
            let origin_key_chirho = SigningKey::from_bytes(&[self.origin_seed_chirho; 32]);
            let target_key_chirho = SigningKey::from_bytes(&[0x52; 32]);
            let origin_id_chirho = hex_chirho(origin_key_chirho.verifying_key().as_bytes());
            let target_id_chirho = hex_chirho(target_key_chirho.verifying_key().as_bytes());
            let group_chirho =
                relay_tenant_consistency_group_digest_chirho(TENANT_CHIRHO).expect("tenant group");
            let roster_chirho = roster_for_seeds_chirho(&self.roster_seeds_chirho);
            let prepared_chirho = PreparedServedWriteRelayRequestV1Chirho::new_chirho(
                ServedWriteRelayRequestInputChirho {
                    ingress_admission_chirho: input_chirho.ingress_admission_chirho,
                    origin_node_id_chirho: origin_id_chirho,
                    target_node_id_chirho: target_id_chirho.clone(),
                    consistency_group_digest_chirho: group_chirho.clone(),
                    expected_term_chirho: TERM_CHIRHO,
                    caller_idempotency_key_chirho: input_chirho.caller_idempotency_key_chirho,
                    method_chirho: input_chirho.method_chirho,
                    uri_chirho: input_chirho.uri_chirho,
                    end_to_end_headers_chirho: input_chirho.end_to_end_headers_chirho,
                    body_chirho: input_chirho.body_chirho,
                    relay_budget_remaining_millis_chirho: 2_500,
                },
            )
            .expect("bounded prepared request");
            let signature_chirho = origin_key_chirho.sign(&prepared_chirho.signing_digest_chirho());
            let signed_chirho = prepared_chirho
                .into_signed_chirho(hex_chirho(&signature_chirho.to_bytes()))
                .expect("signed request");
            let request_chirho = decode_and_verify_served_write_relay_request_chirho(
                &signed_chirho.to_wire_bytes_chirho().expect("request wire"),
                &group_chirho,
                &target_id_chirho,
                &roster_chirho,
            )
            .expect("destination verifies origin signature");
            self.destination_calls_chirho.fetch_add(1, Ordering::SeqCst);
            let result_chirho: RelayDestinationResponseChirho = self
                .destination_chirho
                .execute_verified_chirho(&request_chirho)
                .await;
            if matches!(self.mode_chirho, TransportModeChirho::LoseResponseChirho) {
                return Err(
                    RelayTransportFailureChirho::response_unavailable_after_execution_chirho()
                        .into(),
                );
            }
            let (class_chirho, identity_chirho, status_chirho, headers_chirho, body_chirho) =
                result_chirho.into_parts_chirho();
            let prepared_chirho = PreparedServedWriteRelayResponseV1Chirho::new_chirho(
                ServedWriteRelayResponseInputChirho {
                    request_digest_chirho: request_chirho.request_digest_chirho().to_string(),
                    caller_idempotency_key_digest_chirho: request_chirho
                        .caller_idempotency_key_chirho()
                        .digest_hex_chirho(),
                    responder_node_id_chirho: target_id_chirho.clone(),
                    consistency_group_digest_chirho: group_chirho.clone(),
                    actual_term_chirho: TERM_CHIRHO,
                    outcome_class_chirho: class_chirho,
                    outcome_identity_chirho: identity_chirho,
                    status_chirho,
                    end_to_end_headers_chirho: headers_chirho,
                    body_chirho,
                },
            )
            .expect("prepared real destination response");
            let signature_chirho = target_key_chirho.sign(&prepared_chirho.signing_digest_chirho());
            let signed_chirho = prepared_chirho
                .into_signed_chirho(hex_chirho(&signature_chirho.to_bytes()))
                .expect("signed response");
            let response_chirho = decode_and_verify_served_write_relay_response_chirho(
                &signed_chirho.to_wire_bytes_chirho().expect("response wire"),
                request_chirho.request_digest_chirho(),
                &request_chirho
                    .caller_idempotency_key_chirho()
                    .digest_hex_chirho(),
                &group_chirho,
                &target_id_chirho,
                &roster_chirho,
            )
            .expect("origin verifies destination signature and request binding");
            Ok(ServedWriteDispatchOutcomeChirho::RelayedChirho(Box::new(
                response_chirho,
            )))
        })
    }
}

fn corrupt_follower_chirho(fixture_chirho: &FixtureChirho) {
    std::fs::write(
        fixture_chirho.root_chirho.join("refs-chirho.json"),
        b"not refs JSON-chirho",
    )
    .expect("stale follower refs");
    std::fs::write(
        fixture_chirho
            .root_chirho
            .join("identity-sessions-chirho.jsonl"),
        b"not a session row-chirho\n",
    )
    .expect("stale follower sessions");
}

fn ingress_scope_chirho(owner_chirho: bool) -> RelayIngressScopeChirho {
    scope_for_seeds_chirho(if owner_chirho { 0x52 } else { 0x31 }, &[0x31, 0x52])
}

fn roster_for_seeds_chirho(seeds_chirho: &[u8]) -> RelayRosterChirho {
    RelayRosterChirho::new_chirho(seeds_chirho.iter().map(|seed_chirho| {
        hex_chirho(
            SigningKey::from_bytes(&[*seed_chirho; 32])
                .verifying_key()
                .as_bytes(),
        )
    }))
    .expect("test roster")
}

fn scope_for_seeds_chirho(local_seed_chirho: u8, seeds_chirho: &[u8]) -> RelayIngressScopeChirho {
    RelayIngressScopeChirho::new_chirho(
        hex_chirho(
            SigningKey::from_bytes(&[local_seed_chirho; 32])
                .verifying_key()
                .as_bytes(),
        ),
        relay_tenant_consistency_group_digest_chirho(TENANT_CHIRHO).expect("tenant group"),
        &roster_for_seeds_chirho(seeds_chirho),
    )
    .expect("fixed ingress scope")
}

#[path = "body_tests_chirho.rs"]
mod body_tests_chirho;
#[path = "ingress_tests_chirho.rs"]
mod ingress_tests_chirho;
#[path = "owner_tests_chirho.rs"]
mod owner_tests_chirho;
#[path = "relay_tests_chirho.rs"]
mod relay_tests_chirho;
