// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use axum::body::to_bytes;
use axum::extract::{Path as AxPath, State};
use cairn_chirho::model_chirho::{CapabilityChirho, DagChirho, HashChirho, NodeDefChirho};
use cairn_write_relay_chirho::{
    RelayContractErrorChirho, ServedLocalReadAuthorityPortChirho,
    ServedLocalReadAuthorityWitnessChirho, ServedWriteDispatchFutureChirho,
    ServedWriteDispatchInputChirho, ServedWriteDispatchOutcomeChirho,
    ServedWriteDispatchPortChirho, ServedWriteRelayFailureChirho,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const APP_CHIRHO: &str = "elected-read-fixture-chirho";
const OWNER_NODE_CHIRHO: &str = "elected-read-owner-node-chirho";
const TERM_CHIRHO: u64 = 7;

enum StubReadAuthorityOutcomeChirho {
    StableChirho,
    BeginNonOwnerChirho,
    ConfirmTermChangedChirho,
}

struct StubReadAuthorityChirho {
    begin_calls_chirho: AtomicUsize,
    confirm_calls_chirho: AtomicUsize,
    outcome_chirho: StubReadAuthorityOutcomeChirho,
}

impl StubReadAuthorityChirho {
    fn new_chirho(outcome_chirho: StubReadAuthorityOutcomeChirho) -> Arc<Self> {
        Arc::new(Self {
            begin_calls_chirho: AtomicUsize::new(0),
            confirm_calls_chirho: AtomicUsize::new(0),
            outcome_chirho,
        })
    }

    fn begin_calls_chirho(&self) -> usize {
        self.begin_calls_chirho.load(Ordering::Acquire)
    }

    fn confirm_calls_chirho(&self) -> usize {
        self.confirm_calls_chirho.load(Ordering::Acquire)
    }
}

impl ServedLocalReadAuthorityPortChirho for StubReadAuthorityChirho {
    fn begin_local_read_chirho(
        &self,
    ) -> Result<ServedLocalReadAuthorityWitnessChirho, ServedWriteRelayFailureChirho> {
        self.begin_calls_chirho.fetch_add(1, Ordering::AcqRel);
        match self.outcome_chirho {
            StubReadAuthorityOutcomeChirho::BeginNonOwnerChirho => {
                Err(RelayContractErrorChirho::local_authority_unavailable_chirho().into())
            }
            StubReadAuthorityOutcomeChirho::StableChirho
            | StubReadAuthorityOutcomeChirho::ConfirmTermChangedChirho => {
                Ok(ServedLocalReadAuthorityWitnessChirho::new_chirho(
                    OWNER_NODE_CHIRHO.to_string(),
                    TERM_CHIRHO,
                ))
            }
        }
    }

    fn confirm_local_read_chirho(
        &self,
        _witness_chirho: &ServedLocalReadAuthorityWitnessChirho,
    ) -> Result<(), ServedWriteRelayFailureChirho> {
        let prior_calls_chirho = self.confirm_calls_chirho.fetch_add(1, Ordering::AcqRel);
        match self.outcome_chirho {
            StubReadAuthorityOutcomeChirho::ConfirmTermChangedChirho if prior_calls_chirho > 0 => {
                Err(RelayContractErrorChirho::owner_term_changed_chirho().into())
            }
            StubReadAuthorityOutcomeChirho::StableChirho
            | StubReadAuthorityOutcomeChirho::BeginNonOwnerChirho
            | StubReadAuthorityOutcomeChirho::ConfirmTermChangedChirho => Ok(()),
        }
    }
}

struct CountingWriteDispatchChirho {
    calls_chirho: AtomicUsize,
}

impl CountingWriteDispatchChirho {
    fn new_chirho() -> Arc<Self> {
        Arc::new(Self {
            calls_chirho: AtomicUsize::new(0),
        })
    }

    fn calls_chirho(&self) -> usize {
        self.calls_chirho.load(Ordering::Acquire)
    }
}

impl ServedWriteDispatchPortChirho for CountingWriteDispatchChirho {
    fn dispatch_chirho<'a>(
        &'a self,
        _input_chirho: ServedWriteDispatchInputChirho,
    ) -> ServedWriteDispatchFutureChirho<'a> {
        self.calls_chirho.fetch_add(1, Ordering::AcqRel);
        Box::pin(async { Ok(ServedWriteDispatchOutcomeChirho::ExecuteLocallyChirho) })
    }
}

struct TestTenantRootChirho {
    platform_root_chirho: PathBuf,
    tenant_root_chirho: PathBuf,
}

impl TestTenantRootChirho {
    fn new_chirho(label_chirho: &str) -> Self {
        let stamp_chirho = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock after epoch")
            .as_nanos();
        let platform_root_chirho = std::env::temp_dir().join(format!(
            "cairn-elected-ssr-{label_chirho}-{}-{stamp_chirho}",
            std::process::id()
        ));
        let tenant_root_chirho = cairn_chirho::tenant_chirho::root_for_tenant_chirho(
            &platform_root_chirho,
            &TenantIdChirho::TenantChirho(format!("{label_chirho}-chirho")),
        )
        .expect("test tenant root");
        Self {
            platform_root_chirho,
            tenant_root_chirho,
        }
    }

    fn root_chirho(&self) -> &Path {
        &self.tenant_root_chirho
    }
}

impl Drop for TestTenantRootChirho {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.platform_root_chirho);
    }
}

fn store_dag_with_capabilities_chirho(
    root_chirho: &Path,
    capabilities_chirho: Vec<CapabilityChirho>,
) -> HashChirho {
    let wasm_chirho = include_str!("../../../../../../examples-chirho/upcase-chirho.wat");
    let wasm_hash_chirho =
        cairn_chirho::cas_chirho::add_chirho(root_chirho, wasm_chirho.as_bytes())
            .expect("store fixture WASM");
    let node_hash_chirho = cairn_chirho::store_chirho::put_object_chirho(
        root_chirho,
        &NodeDefChirho {
            name_chirho: "elected_ssr_read_fixture_chirho".to_string(),
            impl_wasm_chirho: wasm_hash_chirho,
            entry_chirho: "upcase_chirho".to_string(),
            inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "in_chirho".to_string(),
                schema_chirho: HashChirho("bytes-chirho".to_string()),
            }],
            outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "out_chirho".to_string(),
                schema_chirho: HashChirho("bytes-chirho".to_string()),
            }],
            capabilities_chirho,
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        },
    )
    .expect("store fixture node");
    cairn_chirho::store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .expect("store fixture DAG")
}

fn deploy_app_before_elected_latch_chirho(
    root_chirho: &Path,
    capabilities_chirho: Vec<CapabilityChirho>,
) -> (HashChirho, String) {
    let owner_chirho = cairn_chirho::identity_chirho::register_identity_chirho(
        root_chirho,
        cairn_chirho::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .expect("fixture owner");
    let dag_chirho = store_dag_with_capabilities_chirho(root_chirho, capabilities_chirho);
    cairn_chirho::app_chirho::deploy_app_chirho(
        root_chirho,
        APP_CHIRHO,
        dag_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .expect("deploy fixture app");
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        root_chirho,
        APP_CHIRHO,
        None,
        &owner_chirho.principal_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .expect("set fixture input policy");
    (dag_chirho, owner_chirho.principal_chirho)
}

fn latch_elected_root_chirho(root_chirho: &Path) {
    cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(
        root_chirho,
        TERM_CHIRHO,
    )
    .expect("latch fixture into elected era");
}

fn deploy_elected_app_chirho(
    root_chirho: &Path,
    capabilities_chirho: Vec<CapabilityChirho>,
) -> HashChirho {
    let (dag_chirho, _owner_chirho) =
        deploy_app_before_elected_latch_chirho(root_chirho, capabilities_chirho);
    latch_elected_root_chirho(root_chirho);
    dag_chirho
}

fn install_anonymous_request_resource_gate_chirho(root_chirho: &Path, owner_chirho: &str) {
    cairn_chirho::resource_chirho::set_resource_policy_chirho(
        root_chirho,
        APP_CHIRHO,
        owner_chirho,
        vec![cairn_chirho::resource_chirho::ResourceMeterChirho {
            resource_chirho: "elected-ssr-request-chirho".to_string(),
            unit_chirho: "request-chirho".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: Some(10),
            app_limit_chirho: None,
            window_ms_chirho: None,
            overage_chirho: cairn_chirho::resource_chirho::ResourceOverageChirho::FailClosedChirho,
        }],
        vec![cairn_chirho::resource_chirho::ResourceActionPolicyChirho {
            section_chirho: super::super::REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: super::super::REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: true,
            charges_chirho: vec![cairn_chirho::resource_chirho::ResourceChargeChirho {
                resource_chirho: "elected-ssr-request-chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .expect("install fixture request resource gate");
}

fn deploy_resource_gated_elected_app_chirho(root_chirho: &Path) {
    let (_dag_chirho, owner_chirho) =
        deploy_app_before_elected_latch_chirho(root_chirho, Vec::new());
    install_anonymous_request_resource_gate_chirho(root_chirho, &owner_chirho);
    latch_elected_root_chirho(root_chirho);
}

fn state_with_authorities_chirho(
    root_chirho: &Path,
    read_authority_chirho: Arc<dyn ServedLocalReadAuthorityPortChirho>,
    write_dispatch_chirho: Arc<dyn ServedWriteDispatchPortChirho>,
) -> AppStateChirho {
    super::super::app_state_for_runtime_root_with_effect_runtime_chirho(
        root_chirho,
        super::super::RuntimeAppStateOptionsChirho {
            inflight_limit_chirho: 8,
            auth_tokens_chirho: super::super::ServeAuthTokensChirho::default(),
            domain_routing_enabled_chirho: false,
            served_request_limits_chirho: super::super::ServedRequestAbuseLimitsChirho::default(),
            projection_read_chirho: None,
            postgres_effect_chirho: None,
            llm_served_chirho: None,
            write_dispatch_chirho: Some(write_dispatch_chirho),
            local_read_authority_chirho: Some(read_authority_chirho),
            write_destination_slot_chirho: None,
        },
    )
    .expect("fixture app state")
}

async fn ssr_response_chirho(state_chirho: AppStateChirho) -> (StatusCode, String) {
    let response_chirho = ssr_get_chirho(
        State(state_chirho),
        None,
        axum::http::HeaderMap::new(),
        AxPath(APP_CHIRHO.to_string()),
    )
    .await;
    let status_chirho = response_chirho.status();
    let body_chirho = to_bytes(response_chirho.into_body(), usize::MAX)
        .await
        .expect("read SSR response");
    (
        status_chirho,
        String::from_utf8_lossy(&body_chirho).into_owned(),
    )
}

#[test]
fn exact_balance_capability_classes_are_admitted_without_broadening_chirho() {
    let fixture_chirho = TestTenantRootChirho::new_chirho("capability-shape");
    let dag_chirho = store_dag_with_capabilities_chirho(
        fixture_chirho.root_chirho(),
        vec![
            CapabilityChirho::QueryChirho {
                prefix_chirho: "credits-balance-chirho".to_string(),
                caller_chirho: "credits-demo-spend-role-chirho".to_string(),
                max_rows_chirho: 1,
            },
            CapabilityChirho::UserIdentityChirho {
                principal_chirho: "user/elected-read-chirho".to_string(),
                client_id_chirho: "credits-demo-chirho".to_string(),
                token_hash_chirho: "token-hash-chirho".to_string(),
            },
        ],
    );
    let runtime_chirho =
        super::super::ServedRuntimeRootChirho::new_chirho(fixture_chirho.root_chirho());
    assert!(runtime_chirho
        .dag_is_elected_ssr_read_only_chirho(&dag_chirho)
        .expect("classify exact balance capability set"));

    for forbidden_chirho in [
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "credits-balance-chirho".to_string(),
        },
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "credits-balance-chirho".to_string(),
        },
    ] {
        let forbidden_dag_chirho = store_dag_with_capabilities_chirho(
            fixture_chirho.root_chirho(),
            vec![forbidden_chirho],
        );
        assert!(!runtime_chirho
            .dag_is_elected_ssr_read_only_chirho(&forbidden_dag_chirho)
            .expect("classify forbidden capability"));
    }
}

#[tokio::test]
async fn elected_ssr_read_requires_same_local_authority_before_and_after_execution_chirho() {
    let fixture_chirho = TestTenantRootChirho::new_chirho("stable-owner");
    deploy_elected_app_chirho(fixture_chirho.root_chirho(), Vec::new());
    let usage_path_chirho = fixture_chirho
        .root_chirho()
        .join("resource-usage-chirho.jsonl");
    assert!(!usage_path_chirho.exists());
    let read_authority_chirho =
        StubReadAuthorityChirho::new_chirho(StubReadAuthorityOutcomeChirho::StableChirho);
    let write_dispatch_chirho = CountingWriteDispatchChirho::new_chirho();
    let state_chirho = state_with_authorities_chirho(
        fixture_chirho.root_chirho(),
        read_authority_chirho.clone(),
        write_dispatch_chirho.clone(),
    );

    let (status_chirho, body_chirho) = ssr_response_chirho(state_chirho).await;
    assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
    assert!(body_chirho.contains("<!doctype html>"), "{body_chirho}");
    assert_eq!(read_authority_chirho.begin_calls_chirho(), 1);
    assert_eq!(read_authority_chirho.confirm_calls_chirho(), 2);
    assert_eq!(write_dispatch_chirho.calls_chirho(), 0);
    assert!(
        !usage_path_chirho.exists(),
        "an elected SSR read must not append resource usage"
    );
}

#[tokio::test]
async fn local_ssr_resource_gate_retains_usage_append_chirho() {
    let fixture_chirho = TestTenantRootChirho::new_chirho("local-resource-gated");
    let (_dag_chirho, owner_chirho) =
        deploy_app_before_elected_latch_chirho(fixture_chirho.root_chirho(), Vec::new());
    install_anonymous_request_resource_gate_chirho(fixture_chirho.root_chirho(), &owner_chirho);
    let read_authority_chirho =
        StubReadAuthorityChirho::new_chirho(StubReadAuthorityOutcomeChirho::StableChirho);
    let write_dispatch_chirho = CountingWriteDispatchChirho::new_chirho();
    let state_chirho = state_with_authorities_chirho(
        fixture_chirho.root_chirho(),
        read_authority_chirho.clone(),
        write_dispatch_chirho.clone(),
    );

    let (status_chirho, body_chirho) = ssr_response_chirho(state_chirho).await;
    assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
    assert_eq!(
        cairn_chirho::resource_chirho::load_resource_usage_chirho(fixture_chirho.root_chirho())
            .expect("load local SSR resource usage")
            .len(),
        1,
        "the local-era branch must retain its existing resource-usage append"
    );
    assert_eq!(read_authority_chirho.begin_calls_chirho(), 0);
    assert_eq!(read_authority_chirho.confirm_calls_chirho(), 0);
    assert_eq!(write_dispatch_chirho.calls_chirho(), 0);
}

#[tokio::test]
async fn elected_ssr_resource_gate_refuses_without_usage_append_chirho() {
    let fixture_chirho = TestTenantRootChirho::new_chirho("resource-gated");
    deploy_resource_gated_elected_app_chirho(fixture_chirho.root_chirho());
    assert!(
        cairn_chirho::resource_chirho::current_resource_policy_chirho(
            fixture_chirho.root_chirho(),
            APP_CHIRHO,
        )
        .expect("read fixture resource policy")
        .is_some(),
        "fixture must carry an active request resource gate"
    );
    let usage_path_chirho = fixture_chirho
        .root_chirho()
        .join("resource-usage-chirho.jsonl");
    assert!(!usage_path_chirho.exists());
    let read_authority_chirho =
        StubReadAuthorityChirho::new_chirho(StubReadAuthorityOutcomeChirho::StableChirho);
    let write_dispatch_chirho = CountingWriteDispatchChirho::new_chirho();
    let state_chirho = state_with_authorities_chirho(
        fixture_chirho.root_chirho(),
        read_authority_chirho.clone(),
        write_dispatch_chirho.clone(),
    );

    let (status_chirho, body_chirho) = ssr_response_chirho(state_chirho).await;
    assert_eq!(status_chirho, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_chirho, "error: RelayMutationFamilyUnconvertedChirho\n");
    assert_eq!(read_authority_chirho.begin_calls_chirho(), 1);
    assert_eq!(read_authority_chirho.confirm_calls_chirho(), 0);
    assert_eq!(write_dispatch_chirho.calls_chirho(), 0);
    assert!(
        !usage_path_chirho.exists(),
        "an elected SSR resource gate must refuse without appending usage"
    );
}

#[tokio::test]
async fn elected_ssr_mutation_capability_refuses_before_execution_or_dispatch_chirho() {
    let fixture_chirho = TestTenantRootChirho::new_chirho("mutation-refusal");
    deploy_elected_app_chirho(
        fixture_chirho.root_chirho(),
        vec![CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "credits-chirho".to_string(),
        }],
    );
    let read_authority_chirho =
        StubReadAuthorityChirho::new_chirho(StubReadAuthorityOutcomeChirho::StableChirho);
    let write_dispatch_chirho = CountingWriteDispatchChirho::new_chirho();
    let state_chirho = state_with_authorities_chirho(
        fixture_chirho.root_chirho(),
        read_authority_chirho.clone(),
        write_dispatch_chirho.clone(),
    );

    let (status_chirho, body_chirho) = ssr_response_chirho(state_chirho).await;
    assert_eq!(status_chirho, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_chirho, "error: RelayMutationFamilyUnconvertedChirho\n");
    assert_eq!(read_authority_chirho.begin_calls_chirho(), 1);
    assert_eq!(read_authority_chirho.confirm_calls_chirho(), 0);
    assert_eq!(write_dispatch_chirho.calls_chirho(), 0);
}

#[tokio::test]
async fn elected_ssr_non_owner_refuses_before_dag_execution_chirho() {
    let fixture_chirho = TestTenantRootChirho::new_chirho("non-owner");
    deploy_elected_app_chirho(fixture_chirho.root_chirho(), Vec::new());
    let read_authority_chirho =
        StubReadAuthorityChirho::new_chirho(StubReadAuthorityOutcomeChirho::BeginNonOwnerChirho);
    let write_dispatch_chirho = CountingWriteDispatchChirho::new_chirho();
    let state_chirho = state_with_authorities_chirho(
        fixture_chirho.root_chirho(),
        read_authority_chirho.clone(),
        write_dispatch_chirho.clone(),
    );

    let (status_chirho, body_chirho) = ssr_response_chirho(state_chirho).await;
    assert_eq!(status_chirho, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_chirho, "error: RelayLocalAuthorityUnavailableChirho\n");
    assert_eq!(read_authority_chirho.begin_calls_chirho(), 1);
    assert_eq!(read_authority_chirho.confirm_calls_chirho(), 0);
    assert_eq!(write_dispatch_chirho.calls_chirho(), 0);
}

#[tokio::test]
async fn elected_ssr_term_change_after_execution_suppresses_the_payload_chirho() {
    let fixture_chirho = TestTenantRootChirho::new_chirho("term-change");
    deploy_elected_app_chirho(fixture_chirho.root_chirho(), Vec::new());
    let read_authority_chirho = StubReadAuthorityChirho::new_chirho(
        StubReadAuthorityOutcomeChirho::ConfirmTermChangedChirho,
    );
    let write_dispatch_chirho = CountingWriteDispatchChirho::new_chirho();
    let state_chirho = state_with_authorities_chirho(
        fixture_chirho.root_chirho(),
        read_authority_chirho.clone(),
        write_dispatch_chirho.clone(),
    );

    let (status_chirho, body_chirho) = ssr_response_chirho(state_chirho).await;
    assert_eq!(status_chirho, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_chirho, "error: RelayOwnerTermChangedChirho\n");
    assert!(!body_chirho.contains("<!doctype html>"), "{body_chirho}");
    assert_eq!(read_authority_chirho.begin_calls_chirho(), 1);
    assert_eq!(read_authority_chirho.confirm_calls_chirho(), 2);
    assert_eq!(write_dispatch_chirho.calls_chirho(), 0);
}
