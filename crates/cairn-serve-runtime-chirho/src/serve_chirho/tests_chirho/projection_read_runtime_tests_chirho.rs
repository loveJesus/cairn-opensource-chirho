// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use cairn_ledger_composition_chirho::{
    ComposedProjectionReadChirho, FollowerReadRefusalChirho, FollowerServeOutcomeChirho,
    ProjectionCostClassChirho, ProjectionReadOutcomeChirho, ProjectionWatermarkChirho,
    PublishedProjectionViewChirho,
};
use cairn_ledger_model_chirho::{ids_chirho::DigestChirho, record_chirho::HlcChirho};
use cairn_ledger_read_model_chirho::{
    VerifiedProjectionReadCutChirho, VerifiedProjectionSourceHeadChirho,
};
use std::collections::VecDeque;

struct ServedProjectionReadPortChirho {
    outcomes_chirho: std::sync::Mutex<VecDeque<ComposedProjectionReadChirho>>,
    calls_chirho: std::sync::atomic::AtomicUsize,
}

impl ServedProjectionReadPortChirho {
    fn new_chirho(outcomes_chirho: Vec<ComposedProjectionReadChirho>) -> Self {
        Self {
            outcomes_chirho: std::sync::Mutex::new(outcomes_chirho.into()),
            calls_chirho: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho
    for ServedProjectionReadPortChirho
{
    fn read_published_projection_chirho(
        &self,
        request_chirho: &cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionReadRequestChirho<'_>,
    ) -> anyhow::Result<ComposedProjectionReadChirho> {
        assert_eq!(
            request_chirho.projection_name_chirho,
            "credits-balance-chirho"
        );
        assert_eq!(request_chirho.requested_limit_chirho, 5);
        assert_eq!(
            request_chirho.request_context_chirho.app_chirho,
            "credits-projection-app-chirho"
        );
        self.calls_chirho
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.outcomes_chirho
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("served projection test port exhausted"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ServedMoneySurfaceFingerprintChirho {
    effect_files_chirho: usize,
    volatile_bytes_chirho: u64,
    billing_bytes_chirho: u64,
    legacy_ledger_bytes_chirho: u64,
}

fn served_path_bytes_chirho(path_chirho: &std::path::Path) -> u64 {
    std::fs::metadata(path_chirho)
        .map(|metadata_chirho| metadata_chirho.len())
        .unwrap_or(0)
}

fn served_money_surface_fingerprint_chirho(
    root_chirho: &std::path::Path,
) -> ServedMoneySurfaceFingerprintChirho {
    ServedMoneySurfaceFingerprintChirho {
        effect_files_chirho: std::fs::read_dir(root_chirho.join("effects-chirho"))
            .map(|entries_chirho| entries_chirho.count())
            .unwrap_or(0),
        volatile_bytes_chirho: served_path_bytes_chirho(
            &cairn_chirho::effect_chirho::volatile_effect_records_path_chirho(root_chirho),
        ),
        billing_bytes_chirho: served_path_bytes_chirho(
            &root_chirho.join("billing-usage-chirho.jsonl"),
        ),
        legacy_ledger_bytes_chirho: served_path_bytes_chirho(
            &root_chirho.join("ledger-chirho.jsonl"),
        ),
    }
}

fn served_projection_view_chirho() -> PublishedProjectionViewChirho {
    PublishedProjectionViewChirho {
        descriptor_ref_chirho: DigestChirho("served-descriptor-digest-chirho".to_string()),
        watermark_chirho: ProjectionWatermarkChirho {
            source_family_id_chirho: "credits-family-chirho".to_string(),
            source_seq_chirho: 14,
            source_hlc_chirho: HlcChirho {
                physical_ms_chirho: 1_725_000_000_000,
                logical_chirho: 4,
            },
            signed_prefix_digest_chirho: DigestChirho("served-prefix-digest-chirho".to_string()),
        },
        state_digest_chirho: DigestChirho("served-state-digest-chirho".to_string()),
    }
}

fn served_projection_cut_chirho() -> VerifiedProjectionReadCutChirho {
    let view_chirho = served_projection_view_chirho();
    VerifiedProjectionReadCutChirho {
        descriptor_ref_chirho: view_chirho.descriptor_ref_chirho.clone(),
        view_prefix_chirho: view_chirho.watermark_chirho.clone(),
        current_head_chirho: VerifiedProjectionSourceHeadChirho {
            source_family_id_chirho: view_chirho.watermark_chirho.source_family_id_chirho,
            source_seq_chirho: view_chirho.watermark_chirho.source_seq_chirho,
            source_hlc_chirho: view_chirho.watermark_chirho.source_hlc_chirho,
            signed_prefix_digest_chirho: view_chirho.watermark_chirho.signed_prefix_digest_chirho,
        },
    }
}

fn served_projection_outcomes_chirho() -> Vec<ComposedProjectionReadChirho> {
    vec![
        ComposedProjectionReadChirho {
            view_bytes_chirho: None,
            verified_cost_class_chirho: Some(ProjectionCostClassChirho::StandingWriteRateChirho),
            outcome_chirho: FollowerServeOutcomeChirho::ReadChirho(
                ProjectionReadOutcomeChirho::RefusedChirho(
                    FollowerReadRefusalChirho::StaleBeyondContractChirho {
                        lag_ms_chirho: 9,
                        max_lag_ms_chirho: 5,
                    },
                ),
            ),
        },
        ComposedProjectionReadChirho {
            view_bytes_chirho: Some(br#"{"balance_chirho":19}"#.to_vec()),
            verified_cost_class_chirho: Some(ProjectionCostClassChirho::StandingWriteRateChirho),
            outcome_chirho: FollowerServeOutcomeChirho::ReadChirho(
                ProjectionReadOutcomeChirho::fresh_from_verified_cut_chirho(
                    &served_projection_cut_chirho(),
                    served_projection_view_chirho(),
                    0,
                ),
            ),
        },
    ]
}

fn store_served_projection_dag_chirho(root_chirho: &std::path::Path) -> HashChirho {
    let schema_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: "served_projection_query_chirho".to_string(),
        impl_wasm_chirho: cas_chirho::add_chirho(root_chirho, b"projection-port-chirho").unwrap(),
        entry_chirho: "served_projection_query_chirho".to_string(),
        inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "in_chirho".to_string(),
            schema_chirho: schema_chirho.clone(),
        }],
        outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "out_chirho".to_string(),
            schema_chirho,
        }],
        capabilities_chirho: vec![CapabilityChirho::QueryChirho {
            prefix_chirho: "credits-balance-chirho".to_string(),
            caller_chirho: "untrusted-caller-string-chirho".to_string(),
            max_rows_chirho: 25,
        }],
        fuel_limit_chirho: 0,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap()
}

fn projection_invoke_body_chirho() -> Vec<u8> {
    let request_chirho =
        serde_json::to_string(&cairn_chirho::effect_chirho::ScopedQueryRequestChirho {
            prefix_chirho: "credits-balance-chirho".to_string(),
            limit_chirho: Some(5),
        })
        .unwrap();
    serde_json::to_vec(&serde_json::json!({
        "target_chirho": "credits-projection-app-chirho",
        "payload_chirho": request_chirho,
    }))
    .unwrap()
}

fn projection_payload_response_chirho(
    response_chirho: &HttpSmokeResponseChirho,
) -> cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionReadResponseChirho {
    assert_eq!(
        response_chirho.status_chirho,
        200,
        "{}",
        String::from_utf8_lossy(&response_chirho.body_chirho)
    );
    let outer_chirho: serde_json::Value =
        serde_json::from_slice(&response_chirho.body_chirho).unwrap();
    serde_json::from_str(outer_chirho["payload_chirho"].as_str().unwrap()).unwrap()
}

#[test]
fn served_projection_retry_refreshes_verdict_with_zero_money_or_observation_rows_chirho() {
    let root_chirho = temp_root_chirho("served-projection-read");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let dag_chirho = store_served_projection_dag_chirho(&root_chirho);
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "credits-projection-app-chirho",
        dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "credits-projection-app-chirho",
        None,
        &owner_chirho.principal_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    let (_user_chirho, headers_chirho) = scoped_headers_for_app_chirho(
        &root_chirho,
        "credits-projection-app-chirho",
        &owner_chirho.principal_chirho,
        "served-projection-secret-chirho",
    );
    let authorization_chirho = headers_chirho
        .get(AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let before_chirho = served_money_surface_fingerprint_chirho(&root_chirho);
    let port_chirho = std::sync::Arc::new(ServedProjectionReadPortChirho::new_chirho(
        served_projection_outcomes_chirho(),
    ));
    let body_chirho = projection_invoke_body_chirho();
    let root_for_server_chirho = root_chirho.clone();
    let port_for_server_chirho = port_chirho.clone();

    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let (refused_http_chirho, fresh_http_chirho) = runtime_chirho.block_on(async move {
        let listener_chirho = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_chirho = listener_chirho.local_addr().unwrap().to_string();
        let app_chirho = runtime_router_for_root_with_projection_read_chirho(
            &root_for_server_chirho,
            8,
            String::new(),
            String::new(),
            false,
            ServedRequestAbuseLimitsChirho::default(),
            Some(port_for_server_chirho),
        )
        .unwrap();
        let server_chirho = tokio::spawn(async move {
            axum::serve(
                listener_chirho,
                app_chirho.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let request_headers_chirho = [
            ("content-type", "application/json"),
            ("authorization", authorization_chirho.as_str()),
        ];
        let refused_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/invoke-chirho",
            &request_headers_chirho,
            &body_chirho,
        );
        let fresh_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/invoke-chirho",
            &request_headers_chirho,
            &body_chirho,
        );
        server_chirho.abort();
        (refused_chirho, fresh_chirho)
    });

    let refused_chirho = projection_payload_response_chirho(&refused_http_chirho);
    assert!(refused_chirho.view_chirho.is_none());
    assert!(matches!(
        refused_chirho.outcome_chirho,
        cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionVerdictChirho::ClassifierRefusedChirho { .. }
    ));
    let fresh_chirho = projection_payload_response_chirho(&fresh_http_chirho);
    assert_eq!(
        fresh_chirho.view_chirho,
        Some(serde_json::json!({"balance_chirho": 19}))
    );
    assert!(matches!(
        fresh_chirho.outcome_chirho,
        cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionVerdictChirho::FreshChirho { .. }
    ));
    assert_eq!(
        port_chirho
            .calls_chirho
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_eq!(
        served_money_surface_fingerprint_chirho(&root_chirho),
        before_chirho
    );
    let run_intents_chirho =
        cairn_chirho::effect_chirho::run_intent_chirho::load_run_intent_records_chirho(
            &root_chirho,
        )
        .unwrap();
    assert_eq!(run_intents_chirho.len(), 3);
    assert_eq!(run_intents_chirho[2].status_chirho, "done-chirho");
    assert!(!root_chirho.join("runs-chirho").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}
