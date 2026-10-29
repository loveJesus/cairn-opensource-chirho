// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K1's served witnesses: a limited key runs exactly the routes its app opened for the actions it holds, a refusal
//! writes nothing, legacy keys of an opted-in app are retired and refused on every entry, the viewer-state door holds a
//! key to its resources, a widened route or a route added later does not widen an old key, a redeploy between the gate
//! and selection refuses, and a route no key may reach cannot be opened.
//! Workflow: limited-key authority (K1),
//! `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.

use super::app_route_fixture_chirho::{
    counted_road_runtime_chirho, head_version_chirho, write_request_chirho, STATE_KEY_CHIRHO,
};
use super::limited_key_fixture_chirho::*;
use super::*;

const ROUTE_NOT_OPEN_CHIRHO: &str = "error: key-route-not-open-chirho";
const ACTION_NOT_GRANTED_CHIRHO: &str = "error: key-action-not-granted-chirho";
const AUTHORITY_CHANGED_CHIRHO: &str = "error: key-action-authority-changed-chirho";
const ROUTE_CHANGED_CHIRHO: &str = "error: key-route-changed-chirho";

#[test]
fn a_read_key_reads_its_opened_route_and_is_refused_on_save_and_root_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k1-read", OpeningsChirho::PAGE_CHIRHO, 1);
    let read_chirho = tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO]);
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, page_chirho) =
            get_route_chirho(&state_chirho, &read_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::OK, "{page_chirho}");
        assert_eq!(head_version_chirho(&page_chirho), None, "nothing saved yet");

        let (status_chirho, body_chirho) = post_route_chirho(
            &state_chirho,
            &read_chirho,
            SAVE_ROUTE_CHIRHO,
            write_request_chirho(None, "from a read key"),
        )
        .await;
        assert_eq!(status_chirho, StatusCode::FORBIDDEN);
        assert_eq!(
            identity_line_chirho(&body_chirho),
            ACTION_NOT_GRANTED_CHIRHO
        );

        let (status_chirho, body_chirho) = get_root_chirho(&state_chirho, &read_chirho).await;
        assert_eq!(status_chirho, StatusCode::FORBIDDEN);
        assert_eq!(identity_line_chirho(&body_chirho), ROUTE_NOT_OPEN_CHIRHO);
    });
}

#[test]
fn a_save_key_saves_and_reads_back_its_page_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k1-save", OpeningsChirho::PAGE_CHIRHO, 1);
    let save_chirho = tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO, PAGE_SAVE_CHIRHO]);
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, page_chirho) = post_route_chirho(
            &state_chirho,
            &save_chirho,
            SAVE_ROUTE_CHIRHO,
            write_request_chirho(None, "saved by a key"),
        )
        .await;
        assert_eq!(status_chirho, StatusCode::OK, "{page_chirho}");
        let (status_chirho, page_chirho) =
            get_route_chirho(&state_chirho, &save_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::OK, "{page_chirho}");
        assert_eq!(head_version_chirho(&page_chirho), Some(1));
    });
}

#[test]
fn a_refused_key_request_writes_nothing_while_an_admitted_one_records_its_use_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k1-nowrite", OpeningsChirho::PAGE_CHIRHO, 1);
    let read_chirho = tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO]);
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        // Refusals at the gate: the save action not granted, and the root not open. Nothing anywhere under the root
        // changes: no key use, no usage row, no sealed input, no CAS object, no run.
        let before_chirho = root_snapshot_chirho(&tenant_chirho.root_chirho);
        let (status_chirho, _) = post_route_chirho(
            &state_chirho,
            &read_chirho,
            SAVE_ROUTE_CHIRHO,
            write_request_chirho(None, "refused"),
        )
        .await;
        assert_eq!(status_chirho, StatusCode::FORBIDDEN);
        let (status_chirho, _) = get_root_chirho(&state_chirho, &read_chirho).await;
        assert_eq!(status_chirho, StatusCode::FORBIDDEN);
        assert_eq!(
            root_snapshot_chirho(&tenant_chirho.root_chirho),
            before_chirho,
            "a refused key request changed the root"
        );

        // The control: an admitted request does change it, starting with exactly one recorded use of the key.
        let uses_before_chirho = token_use_count_chirho(&tenant_chirho.root_chirho);
        let (status_chirho, _) =
            get_route_chirho(&state_chirho, &read_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::OK);
        assert_eq!(
            token_use_count_chirho(&tenant_chirho.root_chirho),
            uses_before_chirho + 1
        );
        assert_ne!(
            root_snapshot_chirho(&tenant_chirho.root_chirho),
            before_chirho
        );
    });
}

#[test]
fn legacy_keys_are_retired_at_opt_in_refused_on_every_entry_and_not_reissued_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k1-legacy", OpeningsChirho::NONE_CHIRHO, 1);
    let legacy_chirho = tenant_chirho
        .try_legacy_bearer_chirho(0)
        .expect("a legacy app issues a legacy key");
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, page_chirho) =
            get_route_chirho(&state_chirho, &legacy_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(
            status_chirho,
            StatusCode::OK,
            "before opt-in the legacy key works: {page_chirho}"
        );
    });

    // A K1-era root: a legacy client before the app's first opening, which K4 refuses (built through the seam).
    cairn_chirho::oauth_chirho::with_k1_era_opening_chirho(|| {
        tenant_chirho.deploy_chirho(OpeningsChirho::PAGE_CHIRHO, |_| {})
    });
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        // Retired: its session was revoked at opt-in, so it is no key at all now (and on any engine that honours
        // session revocation).
        for (status_chirho, body_chirho) in [
            get_route_chirho(&state_chirho, &legacy_chirho, VIEW_ROUTE_CHIRHO).await,
            get_root_chirho(&state_chirho, &legacy_chirho).await,
        ] {
            assert_eq!(status_chirho, StatusCode::FORBIDDEN, "{body_chirho}");
            assert_ne!(identity_line_chirho(&body_chirho), ROUTE_NOT_OPEN_CHIRHO);
        }
    });
    let refusal_chirho = tenant_chirho
        .try_legacy_bearer_chirho(0)
        .expect_err("a limited app issues no legacy key");
    assert!(
        refusal_chirho
            .downcast_ref::<oauth_chirho::LegacyKeyForLimitedAppChirho>()
            .is_some(),
        "{refusal_chirho:#}"
    );
}

#[test]
fn the_viewer_state_door_refuses_a_resource_the_grant_does_not_hold_chirho() {
    // The view is opened over another logical key than the one its DAG reads.
    let openings_chirho = OpeningsChirho {
        view_chirho: Some((PAGE_READ_CHIRHO, &["other-key-chirho"])),
        save_chirho: None,
    };
    let tenant_chirho = KeyedTenantChirho::new_chirho("k1-resource", openings_chirho, 1);
    let read_chirho = tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO]);
    let cookie_chirho = tenant_chirho.cookie_chirho(0);
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, body_chirho) =
            get_route_chirho(&state_chirho, &read_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::BAD_REQUEST, "{body_chirho}");
        assert!(!body_chirho.contains(STATE_KEY_CHIRHO), "{body_chirho}");
        // The control: her own browser session reads the very same route.
        let (status_chirho, page_chirho) =
            get_route_chirho(&state_chirho, &cookie_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::OK, "{page_chirho}");
    });
}

#[test]
fn widened_capabilities_under_the_same_action_refuse_the_old_key_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k1-widened", OpeningsChirho::PAGE_CHIRHO, 1);
    let read_chirho = tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO]);
    // The view keeps its name and its page-read opening, but now runs the save's module: it can write.
    tenant_chirho.deploy_chirho(OpeningsChirho::PAGE_CHIRHO, |manifest_chirho| {
        let save_source_chirho =
            route_entry_chirho(manifest_chirho, SAVE_ROUTE_CHIRHO)["source_chirho"].clone();
        route_entry_chirho(manifest_chirho, VIEW_ROUTE_CHIRHO)["source_chirho"] =
            save_source_chirho;
    });
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, body_chirho) =
            get_route_chirho(&state_chirho, &read_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::FORBIDDEN, "{body_chirho}");
        assert_eq!(identity_line_chirho(&body_chirho), AUTHORITY_CHANGED_CHIRHO);
    });
}

#[test]
fn a_route_added_later_under_an_old_action_does_not_join_an_old_key_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k1-joined", OpeningsChirho::PAGE_CHIRHO, 1);
    let read_chirho = tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO]);
    // A second read route, same module, same action name, added after the key was issued.
    tenant_chirho.deploy_chirho(OpeningsChirho::PAGE_CHIRHO, |manifest_chirho| {
        let mut added_chirho = route_entry_chirho(manifest_chirho, VIEW_ROUTE_CHIRHO).clone();
        added_chirho["route_chirho"] = serde_json::Value::from("view-two");
        manifest_chirho["deploy_chirho"]["routes_chirho"]
            .as_array_mut()
            .unwrap()
            .push(added_chirho);
    });
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, body_chirho) =
            get_route_chirho(&state_chirho, &read_chirho, "view-two").await;
        assert_eq!(status_chirho, StatusCode::FORBIDDEN, "{body_chirho}");
        assert_eq!(
            identity_line_chirho(&body_chirho),
            ACTION_NOT_GRANTED_CHIRHO
        );
        // The control: the route the key was issued over still answers it.
        let (status_chirho, _) =
            get_route_chirho(&state_chirho, &read_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::OK);
    });
}

#[test]
fn a_redeploy_between_the_gate_and_selection_refuses_with_409_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k1-recheck", OpeningsChirho::PAGE_CHIRHO, 1);
    let read_chirho = tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO]);
    let state_chirho = tenant_chirho.state_chirho();
    // Hold the request after the gate admitted it and before the app road reads refs: redeploy the view onto the save's
    // module, so the route selection meets another DAG than the one the gate checked.
    let root_chirho = tenant_chirho.root_chirho.clone();
    let redeploy_chirho = std::sync::Arc::new(std::sync::Mutex::new(Some(tenant_chirho)));
    let hook_tenant_chirho = redeploy_chirho.clone();
    crate::serve_chirho::public_error_chirho::hold_points_chirho::set_hold_for_root_chirho(
        crate::serve_chirho::public_error_chirho::hold_points_chirho::HoldPointChirho::BeforeAppRefsReadChirho,
        &root_chirho,
        move || {
            let guard_chirho = hook_tenant_chirho.lock().unwrap();
            guard_chirho
                .as_ref()
                .unwrap()
                .deploy_chirho(OpeningsChirho::PAGE_CHIRHO, |manifest_chirho| {
                    let save_source_chirho =
                        route_entry_chirho(manifest_chirho, SAVE_ROUTE_CHIRHO)["source_chirho"].clone();
                    route_entry_chirho(manifest_chirho, VIEW_ROUTE_CHIRHO)["source_chirho"] =
                        save_source_chirho;
                });
        },
    );
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, body_chirho) =
            get_route_chirho(&state_chirho, &read_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::CONFLICT, "{body_chirho}");
        assert_eq!(identity_line_chirho(&body_chirho), ROUTE_CHANGED_CHIRHO);
    });
    assert!(root_chirho.exists());
    drop(redeploy_chirho);
}

#[test]
fn a_route_holding_a_capability_no_key_may_reach_cannot_be_opened_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k1-ceiling", OpeningsChirho::NONE_CHIRHO, 0);
    // The save's write door moved to a generic store prefix: its data cannot be bound per key, so opening it refuses.
    let refusal_chirho = tenant_chirho
        .try_deploy_chirho(OpeningsChirho::PAGE_CHIRHO, |manifest_chirho| {
            for node_chirho in manifest_chirho["nodes_chirho"].as_array_mut().unwrap() {
                // `get_mut`, never indexing: indexing a node without the key would insert a null there.
                if let Some(capabilities_chirho) = node_chirho
                    .get_mut("capabilities_chirho")
                    .and_then(|value_chirho| value_chirho.as_array_mut())
                {
                    for capability_chirho in capabilities_chirho.iter_mut() {
                        if capability_chirho == "write-store:viewer-state-chirho/" {
                            *capability_chirho =
                                serde_json::Value::from("write-store:rows-chirho/");
                        }
                    }
                }
            }
        })
        .expect_err("an opening over an ineligible capability refuses deploy");
    assert!(
        format!("{refusal_chirho:#}").contains("cannot be opened to keys"),
        "{refusal_chirho:#}"
    );
    // And no opening was recorded: the app is still in legacy mode.
    assert!(cairn_chirho::app_chirho::app_key_authority_record_chirho(
        &tenant_chirho.root_chirho,
        KEYED_APP_CHIRHO
    )
    .unwrap()
    .is_none());
}

/// An SSR GET of the keyed app through the production handler.
async fn ssr_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
) -> (StatusCode, String) {
    super::app_route_fixture_chirho::response_text_chirho(
        ssr_get_chirho(
            State(state_chirho.clone()),
            None,
            headers_chirho.clone(),
            AxPath(KEYED_APP_CHIRHO.to_string()),
        )
        .await,
    )
    .await
}

/// A POST of `/invoke-chirho` at the keyed app through the production handler.
async fn invoke_post_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
) -> (StatusCode, String) {
    super::app_route_fixture_chirho::response_text_chirho(
        invoke_transport_chirho::invoke_chirho(
            State(state_chirho.clone()),
            None,
            headers_chirho.clone(),
            axum::Json(invoke_transport_chirho::WireRequestChirho {
                target_chirho: KEYED_APP_CHIRHO.to_string(),
                payload_chirho: String::new(),
                base_version_chirho: None,
            }),
        )
        .await,
    )
    .await
}

/// One `/ws-chirho` message at the keyed app through the shared invoke helper the socket runs per message.
async fn ws_message_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: Option<&HeaderMap>,
) -> serde_json::Value {
    let text_chirho =
        serde_json::json!({"target_chirho": KEYED_APP_CHIRHO, "payload_chirho": ""}).to_string();
    let answer_chirho = invoke_transport_chirho::process_invoke_json_with_headers_chirho(
        state_chirho,
        &text_chirho,
        headers_chirho,
        None,
    )
    .await;
    serde_json::from_str(&answer_chirho).unwrap()
}

#[test]
fn ssr_invoke_and_ws_refuse_a_limited_key_and_keep_a_legacy_apps_legacy_key_chirho() {
    let limited_tenant_chirho =
        KeyedTenantChirho::new_chirho("k1-alt-limited", OpeningsChirho::PAGE_CHIRHO, 1);
    let read_chirho = limited_tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO]);
    let state_chirho = limited_tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, body_chirho) = ssr_chirho(&state_chirho, &read_chirho).await;
        assert_eq!(status_chirho, StatusCode::FORBIDDEN, "{body_chirho}");
        assert_eq!(identity_line_chirho(&body_chirho), ROUTE_NOT_OPEN_CHIRHO);
        let (status_chirho, body_chirho) = invoke_post_chirho(&state_chirho, &read_chirho).await;
        assert_eq!(status_chirho, StatusCode::FORBIDDEN, "{body_chirho}");
        assert!(
            body_chirho.contains("key-route-not-open-chirho"),
            "{body_chirho}"
        );
        let answer_chirho = ws_message_chirho(&state_chirho, Some(&read_chirho)).await;
        assert_eq!(answer_chirho["ok_chirho"], false, "{answer_chirho}");
    });

    // The control: on an app that opens nothing, a legacy key keeps today's meaning on the same entries.
    let legacy_tenant_chirho =
        KeyedTenantChirho::new_chirho("k1-alt-legacy", OpeningsChirho::NONE_CHIRHO, 1);
    let legacy_chirho = legacy_tenant_chirho.try_legacy_bearer_chirho(0).unwrap();
    let state_chirho = legacy_tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, body_chirho) = ssr_chirho(&state_chirho, &legacy_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
        let (status_chirho, body_chirho) = invoke_post_chirho(&state_chirho, &legacy_chirho).await;
        assert!(
            !body_chirho.contains("key-route-not-open-chirho"),
            "{status_chirho}: {body_chirho}"
        );
    });
}

#[test]
fn anonymous_callers_meet_the_signed_in_policy_on_ssr_invoke_and_ws_chirho() {
    // A plain-input, signed-in-only app: no private input mode stands in front of the policy here.
    let tenant_chirho = KeyedTenantChirho::new_with_chirho(
        "k1-anon",
        OpeningsChirho::NONE_CHIRHO,
        1,
        |manifest_chirho| {
            manifest_chirho["deploy_chirho"]["input_mode_chirho"] =
                serde_json::json!({"kind_chirho": "plain-chirho"});
        },
    );
    let cookie_chirho = tenant_chirho.cookie_chirho(0);
    let anonymous_chirho = HeaderMap::new();
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, body_chirho) = ssr_chirho(&state_chirho, &anonymous_chirho).await;
        assert_eq!(status_chirho, StatusCode::UNAUTHORIZED, "{body_chirho}");
        let (status_chirho, body_chirho) =
            invoke_post_chirho(&state_chirho, &anonymous_chirho).await;
        assert_eq!(status_chirho, StatusCode::UNAUTHORIZED, "{body_chirho}");
        for headers_chirho in [None, Some(&anonymous_chirho)] {
            let answer_chirho = ws_message_chirho(&state_chirho, headers_chirho).await;
            assert_eq!(
                answer_chirho["payload_chirho"], "unauthorized: authentication required",
                "{answer_chirho}"
            );
        }
        // The control: her signed-in session passes the policy on SSR and the socket.
        let (status_chirho, body_chirho) = ssr_chirho(&state_chirho, &cookie_chirho).await;
        assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
        let answer_chirho = ws_message_chirho(&state_chirho, Some(&cookie_chirho)).await;
        assert_ne!(
            answer_chirho["payload_chirho"],
            "unauthorized: authentication required"
        );
    });
}

#[test]
fn each_viewers_key_reaches_only_that_viewers_page_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k1-viewers", OpeningsChirho::PAGE_CHIRHO, 2);
    let first_save_chirho =
        tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO, PAGE_SAVE_CHIRHO]);
    let second_read_chirho = tenant_chirho.limited_bearer_chirho(1, &[PAGE_READ_CHIRHO]);
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, _) = post_route_chirho(
            &state_chirho,
            &first_save_chirho,
            SAVE_ROUTE_CHIRHO,
            write_request_chirho(None, "the first viewer's page"),
        )
        .await;
        assert_eq!(status_chirho, StatusCode::OK);
        // The page travels base64-encoded, so that is the form the second viewer's page must not carry.
        let encoded_chirho = BASE64_CHIRHO.encode("the first viewer's page".as_bytes());
        // The positive control: the first viewer's own key reads the page back, so the save landed somewhere a key
        // can reach, and the second viewer's empty page below is isolation rather than a save that went nowhere.
        let (status_chirho, own_page_chirho) =
            get_route_chirho(&state_chirho, &first_save_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::OK, "{own_page_chirho}");
        assert_eq!(head_version_chirho(&own_page_chirho), Some(1));
        assert!(
            own_page_chirho.contains(&encoded_chirho),
            "{own_page_chirho}"
        );
        let (status_chirho, page_chirho) =
            get_route_chirho(&state_chirho, &second_read_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::OK, "{page_chirho}");
        assert_eq!(
            head_version_chirho(&page_chirho),
            None,
            "the second viewer sees no page of the first's"
        );
        assert!(!page_chirho.contains(&encoded_chirho), "{page_chirho}");
    });
}

#[test]
fn a_corrupt_key_authority_log_refuses_every_bearer_and_leaves_sessions_working_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k1-corrupt", OpeningsChirho::PAGE_CHIRHO, 1);
    let read_chirho = tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO]);
    let cookie_chirho = tenant_chirho.cookie_chirho(0);
    let path_chirho =
        cairn_chirho::app_chirho::app_key_authority_records_path_chirho(&tenant_chirho.root_chirho);
    let mut log_chirho = std::fs::OpenOptions::new()
        .append(true)
        .open(&path_chirho)
        .unwrap();
    std::io::Write::write_all(&mut log_chirho, b"{\"not\":\"a key-authority record\"}\n").unwrap();
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        // The app's mode cannot be known, so no key is admitted, and it is never read as legacy mode either.
        let (status_chirho, body_chirho) =
            get_route_chirho(&state_chirho, &read_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::FORBIDDEN, "{body_chirho}");
        let (status_chirho, page_chirho) =
            get_route_chirho(&state_chirho, &cookie_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::OK, "{page_chirho}");
    });
}

#[test]
fn the_json_road_issues_no_legacy_key_for_an_opened_app_and_says_why_chirho() {
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("k1-json-road", OpeningsChirho::NONE_CHIRHO, 1);
    let (principal_chirho, credential_chirho) = tenant_chirho.user_chirho(0);
    let request_chirho = |credential_chirho: &str| {
        serde_json::to_vec(&serde_json::json!({
            "principal_chirho": principal_chirho,
            "credential_chirho": credential_chirho,
            "client_id_chirho": tenant_chirho.client_id_chirho,
            "scopes_chirho": [],
        }))
        .unwrap()
    };
    let json_chirho = [("content-type", "application/json")];
    // The control: before the app opens a route, the same request on the real router issues a legacy key.
    with_successor_served_chirho(&tenant_chirho.root_chirho, |addr_chirho| {
        let (status_chirho, body_chirho) = probe_chirho(
            addr_chirho,
            "POST",
            "/auth-chirho/token-chirho",
            &json_chirho,
            &request_chirho(credential_chirho),
        );
        assert_eq!(status_chirho, 200, "{body_chirho}");
    });
    // A K1-era root: a legacy client before the app's first opening, which K4 refuses (built through the seam).
    cairn_chirho::oauth_chirho::with_k1_era_opening_chirho(|| {
        tenant_chirho.deploy_chirho(OpeningsChirho::PAGE_CHIRHO, |_| {})
    });
    let refusal_sentence_chirho = oauth_chirho::LegacyKeyForLimitedAppChirho.to_string();
    with_successor_served_chirho(&tenant_chirho.root_chirho, |addr_chirho| {
        // A right credential is told why, not that it is wrong; a wrong one meets the same answer, because the
        // refusal is decided from the client's app before any credential work and says nothing about the account.
        let mut answers_chirho = Vec::new();
        for credential_chirho in [credential_chirho, "not-this-user-credential"] {
            let (status_chirho, body_chirho) = probe_chirho(
                addr_chirho,
                "POST",
                "/auth-chirho/token-chirho",
                &json_chirho,
                &request_chirho(credential_chirho),
            );
            assert_eq!(status_chirho, 400, "{body_chirho}");
            assert!(
                body_chirho.contains(&refusal_sentence_chirho),
                "{body_chirho}"
            );
            answers_chirho.push(body_chirho);
        }
        assert_eq!(answers_chirho[0], answers_chirho[1]);
    });
}

/// A viewer-state request body as the save route's guest passes it to the door.
fn viewer_state_request_chirho(
    action_chirho: &str,
    key_chirho: &str,
    value_chirho: Option<&str>,
    restore_from_chirho: Option<u64>,
    expected_chirho: Option<u64>,
) -> String {
    let mut request_chirho = serde_json::json!({
        "schema_chirho": "viewer-state-request-v1-chirho",
        "action_chirho": action_chirho,
        "key_chirho": key_chirho,
    });
    if let Some(value_chirho) = value_chirho {
        request_chirho["value_base64_chirho"] =
            serde_json::Value::from(BASE64_CHIRHO.encode(value_chirho.as_bytes()));
    }
    if let Some(restore_from_chirho) = restore_from_chirho {
        request_chirho["restore_from_version_chirho"] =
            serde_json::Value::from(restore_from_chirho);
    }
    // The door's optimistic check: a mutation names the head it expects (none for a key not yet written).
    if let Some(expected_chirho) = expected_chirho {
        request_chirho["expected_current_version_chirho"] =
            serde_json::Value::from(expected_chirho);
    }
    request_chirho.to_string()
}

#[test]
fn a_limited_key_cannot_restore_while_the_viewers_session_can_and_the_saved_head_holds_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k1-restore", OpeningsChirho::PAGE_CHIRHO, 1);
    let save_chirho = tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO, PAGE_SAVE_CHIRHO]);
    let cookie_chirho = tenant_chirho.cookie_chirho(0);
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        // The allowed Save control: the key saves two versions.
        for (expected_chirho, text_chirho) in
            [(None, "the first version"), (Some(1), "the second version")]
        {
            let (status_chirho, body_chirho) = post_route_chirho(
                &state_chirho,
                &save_chirho,
                SAVE_ROUTE_CHIRHO,
                write_request_chirho(expected_chirho, text_chirho),
            )
            .await;
            assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
        }
        let (status_chirho, before_chirho) =
            get_route_chirho(&state_chirho, &cookie_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::OK, "{before_chirho}");
        assert_eq!(head_version_chirho(&before_chirho), Some(2));
        // The key asks the door to restore version 1: refused, and the saved head is exactly as it was.
        let restore_chirho =
            viewer_state_request_chirho("restore-chirho", STATE_KEY_CHIRHO, None, Some(1), Some(2));
        let (status_chirho, body_chirho) = post_route_chirho(
            &state_chirho,
            &save_chirho,
            SAVE_ROUTE_CHIRHO,
            restore_chirho.clone(),
        )
        .await;
        assert_eq!(status_chirho, StatusCode::BAD_REQUEST, "{body_chirho}");
        let (_, after_chirho) =
            get_route_chirho(&state_chirho, &cookie_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(
            after_chirho, before_chirho,
            "the refused restore changed the saved head"
        );
        // The browser control: her own session restores version 1, which becomes version 3.
        let (status_chirho, body_chirho) = post_route_chirho(
            &state_chirho,
            &cookie_chirho,
            SAVE_ROUTE_CHIRHO,
            restore_chirho,
        )
        .await;
        assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
        let (_, restored_chirho) =
            get_route_chirho(&state_chirho, &cookie_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(head_version_chirho(&restored_chirho), Some(3));
        assert!(
            restored_chirho.contains(&BASE64_CHIRHO.encode("the first version".as_bytes())),
            "{restored_chirho}"
        );
    });
}

#[test]
fn a_limited_key_cannot_write_outside_its_grant_while_the_viewers_session_can_chirho() {
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("k1-out-of-grant", OpeningsChirho::PAGE_CHIRHO, 1);
    let save_chirho = tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO, PAGE_SAVE_CHIRHO]);
    let cookie_chirho = tenant_chirho.cookie_chirho(0);
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        // The allowed Save control: the key saves the key its grant names.
        let (status_chirho, body_chirho) = post_route_chirho(
            &state_chirho,
            &save_chirho,
            SAVE_ROUTE_CHIRHO,
            write_request_chirho(None, "the granted page"),
        )
        .await;
        assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
        let (_, before_chirho) =
            get_route_chirho(&state_chirho, &cookie_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(head_version_chirho(&before_chirho), Some(1));
        // The key writes another logical key through the same route: the door refuses, and the saved head holds.
        let (status_chirho, body_chirho) = post_route_chirho(
            &state_chirho,
            &save_chirho,
            SAVE_ROUTE_CHIRHO,
            viewer_state_request_chirho(
                "write-chirho",
                "other-key-chirho",
                Some("out of grant"),
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status_chirho, StatusCode::BAD_REQUEST, "{body_chirho}");
        let (_, after_chirho) =
            get_route_chirho(&state_chirho, &cookie_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(
            after_chirho, before_chirho,
            "the refused write changed the saved head"
        );
        // The browser control, which also shows the refused write left nothing behind: her session's write of that
        // key is its first version.
        let (status_chirho, saved_chirho) = post_route_chirho(
            &state_chirho,
            &cookie_chirho,
            SAVE_ROUTE_CHIRHO,
            viewer_state_request_chirho(
                "write-chirho",
                "other-key-chirho",
                Some("her own page"),
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status_chirho, StatusCode::OK, "{saved_chirho}");
        assert_eq!(
            head_version_chirho(&saved_chirho),
            Some(1),
            "{saved_chirho}"
        );
    });
}

#[test]
fn an_authority_log_that_cannot_be_examined_refuses_a_legacy_bearer_and_leaves_sessions_working_chirho(
) {
    // A legacy-era app: no authority log yet, and a legacy key that works.
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("k1-unexaminable", OpeningsChirho::NONE_CHIRHO, 1);
    let legacy_chirho = tenant_chirho
        .try_legacy_bearer_chirho(0)
        .expect("an app that opens nothing issues legacy keys");
    let cookie_chirho = tenant_chirho.cookie_chirho(0);
    // A symlink looping onto itself where the log belongs: the mode cannot be known, so it is not the legacy era.
    let path_chirho =
        cairn_chirho::app_chirho::app_key_authority_records_path_chirho(&tenant_chirho.root_chirho);
    std::os::unix::fs::symlink(&path_chirho, &path_chirho).unwrap();
    let state_chirho = tenant_chirho.state_chirho();
    counted_road_runtime_chirho().block_on(async {
        let (status_chirho, body_chirho) =
            get_route_chirho(&state_chirho, &legacy_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::FORBIDDEN, "{body_chirho}");
        let (status_chirho, page_chirho) =
            get_route_chirho(&state_chirho, &cookie_chirho, VIEW_ROUTE_CHIRHO).await;
        assert_eq!(status_chirho, StatusCode::OK, "{page_chirho}");
    });
}
