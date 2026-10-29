// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
//! Two-root proof of self-service publication through the served handlers: a signed-in viewer
//! on the TENANT service publishes, republishes, and rolls back through the blessed
//! `template-app-deploy` card; the platform applier (the timer's function) applies; the PUBLIC
//! service serves `/app-chirho/<slug>/` from the latest verified params record. The tenant root
//! never holds the published app (G1), a reserved slug is refused and the refusal reaches her
//! status view, and rollback serves bytes identical to the first publication.

use super::*;
use cairn_chirho::publication_chirho::apply_chirho::{
    apply_publication_intents_chirho, reserve_publication_slug_chirho,
    PublicationApplyReportChirho, ReservedSlugReasonChirho,
};
use cairn_chirho::publication_chirho::status_chirho::PublicationStatusResponseChirho;
use cairn_chirho::publication_chirho::{
    PublicationIntentResponseChirho, PublicationOutcomeChirho,
    PUBLICATION_CAPABILITY_PREFIX_CHIRHO, PUBLICATION_INTENT_EFFECT_CHIRHO,
    PUBLICATION_RESOURCE_ACTION_CHIRHO, PUBLICATION_RESOURCE_SECTION_CHIRHO,
};
use cairn_chirho::resource_chirho::{
    ResourceActionPolicyChirho, ResourceChargeChirho, ResourceMeterChirho, ResourceOverageChirho,
};

const TENANT_CHIRHO: &str = "beta-chirho";
const WORKSPACE_CHIRHO: &str = "perffection-workspace";
const STATUS_ROUTE_CHIRHO: &str = "publication-status";
const TEMPLATE_CHIRHO: &str = "page-template-chirho";
const SLUG_CHIRHO: &str = "good-earth-bakery";

struct TwoRootsChirho {
    platform_chirho: std::path::PathBuf,
    tenant_chirho: std::path::PathBuf,
    headers_chirho: HeaderMap,
}

/// One effect node whose capability is the whole node: the executor dispatches on the
/// capability, so the impl bytes are only a marker (the same shape the write/query fixtures use).
fn effect_dag_chirho(
    root_chirho: &std::path::Path,
    marker_chirho: &str,
    entry_chirho: &str,
    capability_chirho: CapabilityChirho,
) -> HashChirho {
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: entry_chirho.to_string(),
        impl_wasm_chirho: cas_chirho::add_chirho(root_chirho, marker_chirho.as_bytes()).unwrap(),
        entry_chirho: entry_chirho.to_string(),
        inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![capability_chirho],
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

/// A platform root whose registered template is the pure upcase transform (so a served page is
/// the upcased JSON of `{"app_params_chirho": …}` and tracks params byte-for-byte), with one
/// prepared tenant holding the workspace app: root DAG = the publication card, one route = the
/// status read, an admitting resource policy, an authenticated access policy, one user.
fn two_roots_chirho(label_chirho: &str) -> TwoRootsChirho {
    let platform_chirho = temp_root_chirho(label_chirho);
    std::fs::create_dir_all(&platform_chirho).unwrap();
    let template_dag_chirho = store_transform_dag_chirho(
        &platform_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    app_chirho::register_template_app_template_chirho(
        &platform_chirho,
        app_chirho::TemplateRegistryInputChirho {
            template_id_chirho: TEMPLATE_CHIRHO.to_string(),
            root_dag_chirho: template_dag_chirho,
            response_content_type_chirho: "text/html".to_string(),
        },
    )
    .unwrap();
    reserve_publication_slug_chirho(
        &platform_chirho,
        "perffection",
        ReservedSlugReasonChirho::PlatformAppChirho,
    )
    .unwrap();

    let tenant_chirho =
        cairn_chirho::tenant_chirho::prepare_tenant_root_chirho(&platform_chirho, TENANT_CHIRHO)
            .unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &tenant_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let intent_dag_chirho = effect_dag_chirho(
        &tenant_chirho,
        "builtin:template-app-deploy-chirho",
        "template_app_deploy_chirho",
        CapabilityChirho::TemplateAppDeployChirho {
            template_id_chirho: TEMPLATE_CHIRHO.to_string(),
        },
    );
    app_chirho::deploy_app_chirho(
        &tenant_chirho,
        WORKSPACE_CHIRHO,
        intent_dag_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    set_plain_app_input_policy_for_test_chirho(&tenant_chirho, WORKSPACE_CHIRHO, &owner_chirho);
    app_chirho::set_app_request_access_policy_chirho(
        &tenant_chirho,
        WORKSPACE_CHIRHO,
        &owner_chirho,
        intent_dag_chirho,
        app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho,
    )
    .unwrap();
    let status_dag_chirho = effect_dag_chirho(
        &tenant_chirho,
        "builtin:read-store-chirho",
        "read_store_chirho",
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: PUBLICATION_CAPABILITY_PREFIX_CHIRHO.to_string(),
        },
    );
    app_chirho::deploy_app_route_chirho(
        &tenant_chirho,
        WORKSPACE_CHIRHO,
        STATUS_ROUTE_CHIRHO,
        status_dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    app_chirho::set_app_input_policy_chirho(
        &tenant_chirho,
        WORKSPACE_CHIRHO,
        Some(STATUS_ROUTE_CHIRHO),
        &owner_chirho,
        app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    resource_chirho::set_resource_policy_chirho(
        &tenant_chirho,
        WORKSPACE_CHIRHO,
        &owner_chirho,
        vec![ResourceMeterChirho {
            resource_chirho: "publications-chirho".to_string(),
            unit_chirho: "intent-chirho".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: Some(16),
            app_limit_chirho: None,
            window_ms_chirho: None,
            overage_chirho: ResourceOverageChirho::FailClosedChirho,
        }],
        vec![ResourceActionPolicyChirho {
            section_chirho: PUBLICATION_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: PUBLICATION_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: Some(PUBLICATION_INTENT_EFFECT_CHIRHO.to_string()),
            allow_anonymous_chirho: false,
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: "publications-chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap();
    let (_user_chirho, headers_chirho) = scoped_headers_for_app_chirho(
        &tenant_chirho,
        WORKSPACE_CHIRHO,
        &owner_chirho,
        "publication-secret-chirho",
    );
    TwoRootsChirho {
        platform_chirho,
        tenant_chirho,
        headers_chirho,
    }
}

fn intent_body_chirho(
    kind_chirho: &str,
    slug_chirho: &str,
    idem_chirho: &str,
    title_chirho: Option<&str>,
    params_hash_chirho: Option<&HashChirho>,
) -> Vec<u8> {
    let mut request_chirho = serde_json::json!({
        "schema_chirho": "template-app-deploy-request-v1-chirho",
        "kind_chirho": kind_chirho,
        "slug_chirho": slug_chirho,
        "idem_key_chirho": idem_chirho,
    });
    if let Some(title_chirho) = title_chirho {
        request_chirho["params_chirho"] = serde_json::json!({
            "schema_chirho": "page-document-v2-chirho",
            "title_chirho": title_chirho,
        });
    }
    if let Some(hash_chirho) = params_hash_chirho {
        request_chirho["params_hash_chirho"] = serde_json::Value::String(hash_chirho.0.clone());
    }
    serde_json::to_vec(&request_chirho).unwrap()
}

async fn body_chirho(response_chirho: axum::response::Response) -> (StatusCode, Vec<u8>) {
    let status_chirho = response_chirho.status();
    let bytes_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
        .await
        .unwrap();
    (status_chirho, bytes_chirho.to_vec())
}

/// POST the card on the workspace root route as the signed-in viewer.
async fn intend_chirho(
    roots_chirho: &TwoRootsChirho,
    body_bytes_chirho: Vec<u8>,
) -> PublicationIntentResponseChirho {
    let (status_chirho, bytes_chirho) = body_chirho(
        app_post_chirho(
            State(app_state_for_root_chirho(&roots_chirho.tenant_chirho)),
            None,
            roots_chirho.headers_chirho.clone(),
            AxPath(WORKSPACE_CHIRHO.to_string()),
            Bytes::from(body_bytes_chirho),
        )
        .await,
    )
    .await;
    assert_eq!(
        status_chirho,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes_chirho)
    );
    let response_chirho: PublicationIntentResponseChirho =
        serde_json::from_slice(&bytes_chirho).unwrap();
    assert_eq!(
        response_chirho.schema_chirho,
        "publication-intent-response-v1-chirho"
    );
    assert!(
        !response_chirho.applied_chirho,
        "a tenant-root intent is recorded, never applied in place"
    );
    response_chirho
}

/// GET the managed address on a root's public handler with no session at all.
async fn public_page_chirho(
    root_chirho: &std::path::Path,
    slug_chirho: &str,
) -> (StatusCode, Vec<u8>) {
    body_chirho(
        app_get_chirho(
            State(app_state_for_root_chirho(root_chirho)),
            None,
            HeaderMap::new(),
            format!("/app-chirho/{slug_chirho}/").parse().unwrap(),
            AxPath(slug_chirho.to_string()),
        )
        .await,
    )
    .await
}

async fn status_view_chirho(
    roots_chirho: &TwoRootsChirho,
    slug_chirho: &str,
) -> PublicationStatusResponseChirho {
    let request_chirho = serde_json::json!({
        "schema_chirho": "publication-status-request-v1-chirho",
        "slug_chirho": slug_chirho,
    });
    let (status_chirho, bytes_chirho) = body_chirho(
        app_route_post_chirho(
            State(app_state_for_root_chirho(&roots_chirho.tenant_chirho)),
            None,
            roots_chirho.headers_chirho.clone(),
            AxPath((
                WORKSPACE_CHIRHO.to_string(),
                STATUS_ROUTE_CHIRHO.to_string(),
            )),
            Bytes::from(serde_json::to_vec(&request_chirho).unwrap()),
        )
        .await,
    )
    .await;
    assert_eq!(
        status_chirho,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes_chirho)
    );
    serde_json::from_slice(&bytes_chirho).unwrap()
}

/// The timer's function, called in-process between served requests.
fn apply_chirho(roots_chirho: &TwoRootsChirho) -> PublicationApplyReportChirho {
    apply_publication_intents_chirho(&roots_chirho.platform_chirho, TENANT_CHIRHO).unwrap()
}

#[test]
fn a_viewer_publishes_republishes_and_rolls_back_across_two_served_roots_chirho() {
    let roots_chirho = two_roots_chirho("publication-two-roots");
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        // Nothing is served at the managed address before she publishes, on either root.
        assert_eq!(
            public_page_chirho(&roots_chirho.platform_chirho, SLUG_CHIRHO)
                .await
                .0,
            StatusCode::NOT_FOUND
        );

        // 1. publish
        let publish_chirho = intend_chirho(
            &roots_chirho,
            intent_body_chirho(
                "publish-chirho",
                SLUG_CHIRHO,
                "attempt-1",
                Some("Good Earth"),
                None,
            ),
        )
        .await;
        assert_eq!(
            publish_chirho.address_chirho,
            format!("/app-chirho/{SLUG_CHIRHO}/")
        );
        // The intent is recorded but the address stays dark until the platform applies it.
        assert_eq!(
            public_page_chirho(&roots_chirho.platform_chirho, SLUG_CHIRHO)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        let report_chirho = apply_chirho(&roots_chirho);
        assert_eq!(
            (report_chirho.applied_chirho, report_chirho.refused_chirho),
            (1, 0)
        );
        let (status_v1_chirho, page_v1_chirho) =
            public_page_chirho(&roots_chirho.platform_chirho, SLUG_CHIRHO).await;
        assert_eq!(status_v1_chirho, StatusCode::OK);
        let text_v1_chirho = String::from_utf8_lossy(&page_v1_chirho);
        assert!(
            text_v1_chirho.contains("GOOD EARTH") && text_v1_chirho.contains("APP_PARAMS_CHIRHO"),
            "the public page is the template's transform of the published params: {text_v1_chirho}"
        );
        // The published app lives on the platform root only: the tenant root has no such app.
        assert_eq!(
            public_page_chirho(&roots_chirho.tenant_chirho, SLUG_CHIRHO)
                .await
                .0,
            StatusCode::NOT_FOUND,
            "G1: the tenant root never receives the published app"
        );

        // 2. republish: the served bytes change with the new params record.
        intend_chirho(
            &roots_chirho,
            intent_body_chirho(
                "republish-chirho",
                SLUG_CHIRHO,
                "attempt-2",
                Some("Good Earth Bakery"),
                None,
            ),
        )
        .await;
        let report_chirho = apply_chirho(&roots_chirho);
        assert_eq!(
            (
                report_chirho.applied_chirho,
                report_chirho.already_applied_chirho
            ),
            (1, 1)
        );
        let (_status_chirho, page_v2_chirho) =
            public_page_chirho(&roots_chirho.platform_chirho, SLUG_CHIRHO).await;
        assert!(String::from_utf8_lossy(&page_v2_chirho).contains("GOOD EARTH BAKERY"));
        assert_ne!(page_v2_chirho, page_v1_chirho);

        // 3. rollback to her first params record: byte-identical to the first capture.
        intend_chirho(
            &roots_chirho,
            intent_body_chirho(
                "rollback-chirho",
                SLUG_CHIRHO,
                "attempt-3",
                None,
                Some(&publish_chirho.params_chirho),
            ),
        )
        .await;
        let report_chirho = apply_chirho(&roots_chirho);
        assert_eq!(
            (
                report_chirho.applied_chirho,
                report_chirho.already_applied_chirho
            ),
            (1, 2)
        );
        let (_status_chirho, page_v3_chirho) =
            public_page_chirho(&roots_chirho.platform_chirho, SLUG_CHIRHO).await;
        assert_eq!(
            page_v3_chirho, page_v1_chirho,
            "rollback must serve the first bytes exactly"
        );

        // 4. a reserved slug: the intent is accepted on the tenant, refused by the platform, and
        //    the refusal reaches her status view; the reserved address stays dark.
        intend_chirho(
            &roots_chirho,
            intent_body_chirho(
                "publish-chirho",
                "perffection",
                "attempt-4",
                Some("Mine"),
                None,
            ),
        )
        .await;
        let report_chirho = apply_chirho(&roots_chirho);
        assert_eq!(
            (report_chirho.applied_chirho, report_chirho.refused_chirho),
            (0, 1)
        );
        assert_eq!(
            public_page_chirho(&roots_chirho.platform_chirho, "perffection")
                .await
                .0,
            StatusCode::NOT_FOUND
        );

        // 5. her status view, read through the workspace route with her session.
        let view_chirho = status_view_chirho(&roots_chirho, SLUG_CHIRHO).await;
        assert_eq!(
            view_chirho.schema_chirho,
            "publication-status-response-v1-chirho"
        );
        let slug_chirho = &view_chirho.slugs_chirho[0];
        assert_eq!(slug_chirho.slug_chirho, SLUG_CHIRHO);
        assert_eq!(slug_chirho.intents_chirho.len(), 3);
        assert_eq!(slug_chirho.applied_chirho.len(), 3);
        assert!(
            slug_chirho
                .applied_chirho
                .iter()
                .all(|row_chirho| row_chirho.outcome_chirho
                    == PublicationOutcomeChirho::AppliedChirho)
        );
        let live_chirho = slug_chirho
            .live_chirho
            .as_ref()
            .expect("a live publication");
        assert_eq!(
            live_chirho.params_chirho, publish_chirho.params_chirho,
            "after rollback the live params record is the first one"
        );
        let reserved_status_chirho = status_view_chirho(&roots_chirho, "perffection").await;
        let reserved_row_chirho = &reserved_status_chirho.slugs_chirho[0].applied_chirho[0];
        assert_eq!(
            reserved_row_chirho.outcome_chirho,
            PublicationOutcomeChirho::RefusedChirho
        );
        assert_eq!(
            reserved_row_chirho.refusal_code_chirho.as_deref(),
            Some("slug-reserved-chirho")
        );
        assert!(reserved_status_chirho.slugs_chirho[0].live_chirho.is_none());

        // 6. a second tick applies nothing and serves the same bytes.
        let report_chirho = apply_chirho(&roots_chirho);
        assert_eq!(
            (report_chirho.applied_chirho, report_chirho.refused_chirho),
            (0, 0)
        );
        assert_eq!(report_chirho.already_applied_chirho, 4);
        let (_status_chirho, page_again_chirho) =
            public_page_chirho(&roots_chirho.platform_chirho, SLUG_CHIRHO).await;
        assert_eq!(page_again_chirho, page_v1_chirho);
    });

    // Both roots scan clean: the params are the declassified public document by design, and
    // nothing else the flow wrote is free text or a principal in a public log.
    for root_chirho in [&roots_chirho.platform_chirho, &roots_chirho.tenant_chirho] {
        let report_chirho = privacy_chirho::scan_privacy_surfaces_chirho(root_chirho).unwrap();
        assert!(
            report_chirho.findings_chirho.is_empty(),
            "privacy findings on {}: {:?}",
            root_chirho.display(),
            report_chirho.findings_chirho
        );
    }
    let _ = std::fs::remove_dir_all(&roots_chirho.platform_chirho);
}
