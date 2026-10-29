// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The app-route road's fixture for its growth arms: a viewer-state app emitted by the tree builder, served through
//! the production app-route handlers, with the counters an arm reads.
//!
//! Shaped like the product's roads, as PFE measured them (#25824, #25829): an app tree emitted by the tree builder with
//! its guests swapped for WAT, as the beta host packet does. Two routes, every edge private to the requesting user: a
//! GET view (build a read request, read the viewer's state, render) and a POST save (build a write request with
//! expected_version, write, render). Two principals on scoped bearers, on a tenant root (customer writes refuse on the
//! platform root), with the abuse gate's budget raised (it is not on the history axis).

use super::*;
use cairn_chirho::app_chirho::control_log_load_metrics_chirho as control_loads_chirho;
use cairn_chirho::dag_private_value_chirho::private_value_view_metrics_chirho as value_road_chirho;
use cairn_chirho::effect_chirho::run_intent_chirho::run_intent_view_metrics_chirho as run_intent_road_chirho;
use cairn_chirho::privacy_chirho::private_blob_view_metrics_chirho as blob_road_chirho;
use cairn_core_chirho::refs_chirho::reflog_read_metrics_chirho as reflog_reads_chirho;
use cairn_tree_build_chirho::check_chirho::check_app_tree_chirho;
use cairn_tree_build_chirho::emit_chirho::{
    emit_manifest_chirho, AppDescriptorChirho, AppRootChirho, AppRouteChirho,
};
use cairn_tree_build_chirho::tree_chirho::walk_app_tree_chirho;
use std::os::unix::fs::symlink as symlink_chirho;
use std::path::{Path, PathBuf};

pub(super) const GROWTH_APP_CHIRHO: &str = "routegrowth";
const VIEW_ROUTE_CHIRHO: &str = "view";
const SAVE_ROUTE_CHIRHO: &str = "save";
pub(super) const STATE_KEY_CHIRHO: &str = "workspace-chirho";
const REQUEST_TYPE_CHIRHO: &str = "http_request_v1";
const VIEWER_REQUEST_TYPE_CHIRHO: &str = "viewer_state_request_v1";
const VIEWER_RESPONSE_TYPE_CHIRHO: &str = "viewer_state_response_v1";
const PAGE_TYPE_CHIRHO: &str = "html_partial_v1";
const OWN_KEYS_REQUEST_TYPE_CHIRHO: &str = "own_keys_request_v1";
const OWN_KEYS_ANSWER_TYPE_CHIRHO: &str = "own_keys_read_v1";
const PRIVATE_EDGE_CARD_CHIRHO: &str =
    "schema_chirho = \"private-edge-v1-chirho\"\nsubject_source_chirho = \"request-user-chirho\"\n";

/// The identity guest under the bytes ABI: the write request is the POST body, and the rendered page is the
/// viewer-state response itself, so the arm can read the head version from it.
const IDENTITY_WAT_CHIRHO: &str = r#"(module
  (memory (export "memory") 1)
  (global $heap_chirho (mut i32) (i32.const 1024))
  (func (export "alloc_chirho") (param $len i32) (result i32)
    (local $p i32)
    global.get $heap_chirho
    local.set $p
    global.get $heap_chirho
    local.get $len
    i32.add
    global.set $heap_chirho
    local.get $p)
  (func (export "identity_chirho") (param $ptr i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
      (i64.extend_i32_u (local.get $len)))))
"#;

/// The read request the view's build node emits, whatever the (empty) GET input is.
fn read_request_json_chirho() -> String {
    format!(
        "{{\"schema_chirho\":\"viewer-state-request-v1-chirho\",\"action_chirho\":\"read-chirho\",\"key_chirho\":\"{STATE_KEY_CHIRHO}\"}}"
    )
}

/// A guest that returns the read request from a data segment, ignoring its input.
fn read_request_wat_chirho() -> String {
    constant_request_wat_chirho(&read_request_json_chirho(), "emit_read_request_chirho")
}

/// A guest that returns the owner's-keys read request (K3), ignoring its input.
fn own_keys_request_wat_chirho() -> String {
    constant_request_wat_chirho(
        "{\"schema_chirho\":\"own-keys-read-request-v1-chirho\"}",
        "emit_own_keys_request_chirho",
    )
}

/// A guest whose export `entry_chirho` returns `request_chirho` from a data segment, ignoring its input.
fn constant_request_wat_chirho(request_chirho: &str, entry_chirho: &str) -> String {
    let escaped_chirho = request_chirho.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"(module
  (memory (export "memory") 1)
  (global $heap_chirho (mut i32) (i32.const 1024))
  (data (i32.const 0) "{escaped_chirho}")
  (func (export "alloc_chirho") (param $len i32) (result i32)
    (local $p i32)
    global.get $heap_chirho
    local.set $p
    global.get $heap_chirho
    local.get $len
    i32.add
    global.set $heap_chirho
    local.get $p)
  (func (export "{entry_chirho}") (param $ptr i32) (param $len i32) (result i64)
    (i64.const {len_chirho})))
"#,
        len_chirho = request_chirho.len()
    )
}

pub(super) fn tmp_dir_chirho(label_chirho: &str) -> PathBuf {
    let dir_chirho = temp_root_chirho(label_chirho);
    let _ = std::fs::remove_dir_all(&dir_chirho);
    std::fs::create_dir_all(&dir_chirho).unwrap();
    dir_chirho
}

fn role_dir_chirho(app_chirho: &Path, dag_chirho: &str, role_chirho: &str) -> PathBuf {
    app_chirho
        .join("dags_chirho")
        .join(dag_chirho)
        .join("nodes_chirho")
        .join(role_chirho)
}

/// A guest role: its own dir, with the guest source linked in as the tree builder expects.
fn guest_role_chirho(app_chirho: &Path, dag_chirho: &str, role_chirho: &str) -> PathBuf {
    let dir_chirho = role_dir_chirho(app_chirho, dag_chirho, role_chirho);
    std::fs::create_dir_all(&dir_chirho).unwrap();
    std::fs::write(
        app_chirho.join("src").join(format!("{role_chirho}.rs")),
        "// guest source placeholder\n",
    )
    .unwrap();
    symlink_chirho(
        format!("../../../../src/{role_chirho}.rs"),
        dir_chirho.join(format!("{role_chirho}.rs")),
    )
    .unwrap();
    dir_chirho
}

/// A blessed viewer-state door: the catalogued contract, scoped to the viewer's state.
fn blessed_role_chirho(
    app_chirho: &Path,
    dag_chirho: &str,
    role_chirho: &str,
    contract_chirho: &str,
) -> PathBuf {
    blessed_scoped_role_chirho(
        app_chirho,
        dag_chirho,
        role_chirho,
        contract_chirho,
        "viewer-state-chirho/",
        "The signed-in viewer's own bounded state for this app.",
    )
}

/// A blessed door: the catalogued contract at `scope_chirho`, as an app's role card declares it.
fn blessed_scoped_role_chirho(
    app_chirho: &Path,
    dag_chirho: &str,
    role_chirho: &str,
    contract_chirho: &str,
    scope_chirho: &str,
    intent_chirho: &str,
) -> PathBuf {
    let dir_chirho = role_dir_chirho(app_chirho, dag_chirho, role_chirho);
    std::fs::create_dir_all(&dir_chirho).unwrap();
    let contract_hash_chirho =
        cairn_tree_build_chirho::blessed_catalog_chirho::lookup_blessed_contract_chirho(
            contract_chirho,
        )
        .expect("the fixture's contracts are catalogued")
        .contract_hash_chirho();
    std::fs::write(
        dir_chirho.join("blessed-contract-chirho.toml"),
        format!(
            "schema_chirho = \"blessed-card-v2-chirho\"\ncontract_chirho = \"{contract_chirho}\"\ncontract_hash_chirho = \"{contract_hash_chirho}\"\nscope_chirho = \"{scope_chirho}\"\nintent_chirho = \"{intent_chirho}\"\n"
        ),
    )
    .unwrap();
    dir_chirho
}

/// The producer's out dir, marked private to the requesting user (read by each consumer through its symlink).
fn private_out_chirho(dir_chirho: &Path, name_chirho: &str, type_chirho: &str) {
    let out_chirho = dir_chirho.join(format!("out-{name_chirho}-{type_chirho}-chirho"));
    std::fs::create_dir_all(&out_chirho).unwrap();
    std::fs::write(
        out_chirho.join("private-edge-chirho.toml"),
        PRIVATE_EDGE_CARD_CHIRHO,
    )
    .unwrap();
}

fn wire_chirho(
    consumer_chirho: &Path,
    name_chirho: &str,
    type_chirho: &str,
    producer_role_chirho: &str,
    out_name_chirho: &str,
) {
    symlink_chirho(
        format!("../{producer_role_chirho}/out-{out_name_chirho}-{type_chirho}-chirho"),
        consumer_chirho.join(format!("in-{name_chirho}-{type_chirho}-chirho")),
    )
    .unwrap();
}

/// request -> build (guest) -> viewer-state door (blessed) -> render (guest) -> page: the shape of the product's
/// workspace DAGs, every edge private to the requesting user.
pub(super) fn viewer_state_dag_chirho(
    app_chirho: &Path,
    dag_chirho: &str,
    build_role_chirho: &str,
    door_role_chirho: &str,
    contract_chirho: &str,
    render_role_chirho: &str,
) {
    let dag_dir_chirho = app_chirho.join("dags_chirho").join(dag_chirho);
    std::fs::create_dir_all(
        dag_dir_chirho
            .join("surface_chirho")
            .join(format!("in-request-{REQUEST_TYPE_CHIRHO}-chirho")),
    )
    .unwrap();

    let build_chirho = guest_role_chirho(app_chirho, dag_chirho, build_role_chirho);
    symlink_chirho(
        format!("../../surface_chirho/in-request-{REQUEST_TYPE_CHIRHO}-chirho"),
        build_chirho.join(format!("in-request-{REQUEST_TYPE_CHIRHO}-chirho")),
    )
    .unwrap();
    private_out_chirho(&build_chirho, "request", VIEWER_REQUEST_TYPE_CHIRHO);

    let door_chirho =
        blessed_role_chirho(app_chirho, dag_chirho, door_role_chirho, contract_chirho);
    wire_chirho(
        &door_chirho,
        "request",
        VIEWER_REQUEST_TYPE_CHIRHO,
        build_role_chirho,
        "request",
    );
    private_out_chirho(&door_chirho, "state", VIEWER_RESPONSE_TYPE_CHIRHO);

    let render_chirho = guest_role_chirho(app_chirho, dag_chirho, render_role_chirho);
    wire_chirho(
        &render_chirho,
        "state",
        VIEWER_RESPONSE_TYPE_CHIRHO,
        door_role_chirho,
        "state",
    );
    private_out_chirho(&render_chirho, "page", PAGE_TYPE_CHIRHO);
    symlink_chirho(
        format!("../nodes_chirho/{render_role_chirho}/out-page-{PAGE_TYPE_CHIRHO}-chirho"),
        dag_dir_chirho
            .join("surface_chirho")
            .join(format!("out-page-{PAGE_TYPE_CHIRHO}-chirho")),
    )
    .unwrap();
}

/// request -> build (guest) -> the owner's keys (a blessed read-store card at `own-keys-chirho/`) -> render (guest) ->
/// page, every edge private to the requesting user: the shape of the product's Account page (K3).
pub(super) fn own_keys_dag_chirho(
    app_chirho: &Path,
    dag_chirho: &str,
    build_role_chirho: &str,
    door_role_chirho: &str,
    render_role_chirho: &str,
) {
    let dag_dir_chirho = app_chirho.join("dags_chirho").join(dag_chirho);
    std::fs::create_dir_all(
        dag_dir_chirho
            .join("surface_chirho")
            .join(format!("in-request-{REQUEST_TYPE_CHIRHO}-chirho")),
    )
    .unwrap();
    let build_chirho = guest_role_chirho(app_chirho, dag_chirho, build_role_chirho);
    symlink_chirho(
        format!("../../surface_chirho/in-request-{REQUEST_TYPE_CHIRHO}-chirho"),
        build_chirho.join(format!("in-request-{REQUEST_TYPE_CHIRHO}-chirho")),
    )
    .unwrap();
    private_out_chirho(&build_chirho, "request", OWN_KEYS_REQUEST_TYPE_CHIRHO);
    let door_chirho = blessed_scoped_role_chirho(
        app_chirho,
        dag_chirho,
        door_role_chirho,
        "read-store",
        "own-keys-chirho/",
        "The signed-in viewer's own keys, to show and end them.",
    );
    wire_chirho(
        &door_chirho,
        "request",
        OWN_KEYS_REQUEST_TYPE_CHIRHO,
        build_role_chirho,
        "request",
    );
    private_out_chirho(&door_chirho, "keys", OWN_KEYS_ANSWER_TYPE_CHIRHO);
    let render_chirho = guest_role_chirho(app_chirho, dag_chirho, render_role_chirho);
    wire_chirho(
        &render_chirho,
        "keys",
        OWN_KEYS_ANSWER_TYPE_CHIRHO,
        door_role_chirho,
        "keys",
    );
    private_out_chirho(&render_chirho, "page", PAGE_TYPE_CHIRHO);
    symlink_chirho(
        format!("../nodes_chirho/{render_role_chirho}/out-page-{PAGE_TYPE_CHIRHO}-chirho"),
        dag_dir_chirho
            .join("surface_chirho")
            .join(format!("out-page-{PAGE_TYPE_CHIRHO}-chirho")),
    )
    .unwrap();
}

fn private_route_chirho(
    dag_chirho: &str,
    route_chirho: &str,
    accepts_body_chirho: bool,
) -> AppRouteChirho {
    AppRouteChirho {
        dag_chirho: dag_chirho.to_string(),
        input_mode_chirho: "private-blob-ref".to_string(),
        subject_chirho: Some("request-user-chirho".to_string()),
        safe_metadata_chirho: vec![],
        request_body_policy_chirho: accepts_body_chirho.then(|| "accept-body".to_string()),
        route_chirho: route_chirho.to_string(),
        key_access_chirho: None,
        key_action_chirho: None,
        key_resources_chirho: Vec::new(),
    }
}

fn descriptor_chirho(owner_chirho: &str) -> AppDescriptorChirho {
    AppDescriptorChirho {
        app_chirho: GROWTH_APP_CHIRHO.to_string(),
        owner_chirho: owner_chirho.to_string(),
        package_chirho: "routegrowth-chirho".to_string(),
        request_access_policy_chirho: Some("authenticated".to_string()),
        root_chirho: AppRootChirho {
            dag_chirho: "home_chirho".to_string(),
            input_mode_chirho: "private-blob-ref".to_string(),
            subject_chirho: Some("request-user-chirho".to_string()),
            safe_metadata_chirho: vec![],
            request_body_policy_chirho: None,
            route_label_chirho: "home-chirho".to_string(),
            key_access_chirho: None,
        },
        route_chirho: vec![
            private_route_chirho("view_chirho", VIEW_ROUTE_CHIRHO, false),
            private_route_chirho("save_chirho", SAVE_ROUTE_CHIRHO, true),
        ],
        internal_module_chirho: vec![],
        asset_chirho: vec![],
    }
}

/// Swap the emitted cargo-example guests for WAT files, keeping every other emitted byte.
pub(super) fn host_ready_chirho(
    mut manifest_chirho: serde_json::Value,
    guests_chirho: &Path,
) -> serde_json::Value {
    std::fs::write(guests_chirho.join("identity.wat"), IDENTITY_WAT_CHIRHO).unwrap();
    std::fs::write(
        guests_chirho.join("read-request.wat"),
        read_request_wat_chirho(),
    )
    .unwrap();
    std::fs::write(
        guests_chirho.join("own-keys-request.wat"),
        own_keys_request_wat_chirho(),
    )
    .unwrap();
    for node_chirho in manifest_chirho["nodes_chirho"].as_array_mut().unwrap() {
        if node_chirho["source_chirho"]["kind_chirho"] != "cargo-example-chirho" {
            continue;
        }
        let (file_chirho, entry_chirho) = match node_chirho["id_chirho"].as_str().unwrap() {
            "build_read" | "build_home" => ("read-request.wat", "emit_read_request_chirho"),
            "build_keys" => ("own-keys-request.wat", "emit_own_keys_request_chirho"),
            "build_write" | "render_view" | "render_save" | "render_home" | "render_keys" => {
                ("identity.wat", "identity_chirho")
            }
            other_chirho => panic!("unexpected cargo-example node {other_chirho}"),
        };
        node_chirho["source_chirho"] = serde_json::json!({
            "kind_chirho": "path-chirho",
            "path_chirho": guests_chirho.join(file_chirho),
        });
        node_chirho["entry_chirho"] = serde_json::Value::String(entry_chirho.to_string());
    }
    manifest_chirho
}

/// The tenant: the owner's viewer-state app deployed from its emitted manifest, and two users with scoped bearers.
pub(super) struct GrowthTenantChirho {
    pub(super) root_chirho: PathBuf,
    pub(super) owner_chirho: String,
    pub(super) users_chirho: [HeaderMap; 2],
    /// Each user's principal and secret, so an arm can issue that user a second credential.
    pub(super) user_credentials_chirho: [(String, String); 2],
    dirs_chirho: Vec<PathBuf>,
}

impl Drop for GrowthTenantChirho {
    fn drop(&mut self) {
        for dir_chirho in &self.dirs_chirho {
            let _ = std::fs::remove_dir_all(dir_chirho);
        }
    }
}

pub(super) fn deploy_growth_app_chirho(
    root_chirho: &Path,
    owner_chirho: &str,
    label_chirho: &str,
) -> Vec<PathBuf> {
    let app_chirho = tmp_dir_chirho(&format!("{label_chirho}-tree"));
    let guests_chirho = tmp_dir_chirho(&format!("{label_chirho}-guests"));
    std::fs::create_dir_all(app_chirho.join("src")).unwrap();
    // The app root needs a DAG of its own: a route cannot share the root's.
    viewer_state_dag_chirho(
        &app_chirho,
        "home_chirho",
        "build_home_chirho",
        "read_home_chirho",
        "read-store",
        "render_home_chirho",
    );
    viewer_state_dag_chirho(
        &app_chirho,
        "view_chirho",
        "build_read_chirho",
        "read_state_chirho",
        "read-store",
        "render_view_chirho",
    );
    viewer_state_dag_chirho(
        &app_chirho,
        "save_chirho",
        "build_write_chirho",
        "write_state_chirho",
        "write-store",
        "render_save_chirho",
    );
    let tree_chirho = walk_app_tree_chirho(&app_chirho);
    let findings_chirho = check_app_tree_chirho(&tree_chirho);
    assert!(
        findings_chirho.is_empty(),
        "the fixture tree must check clean: {findings_chirho:?}"
    );
    let emitted_chirho =
        emit_manifest_chirho(&tree_chirho, &descriptor_chirho(owner_chirho)).unwrap();
    let manifest_chirho: cairn_chirho::app_source_manifest_chirho::AppSourceManifestChirho =
        serde_json::from_value(host_ready_chirho(emitted_chirho, &guests_chirho))
            .expect("the emitted manifest parses as the engine's app-source model");
    cairn_chirho::app_source_manifest_chirho::deploy_app_source_manifest_chirho(
        root_chirho,
        &guests_chirho,
        &manifest_chirho,
    )
    .expect("the viewer-state fixture deploys");
    vec![app_chirho, guests_chirho]
}

pub(super) fn growth_tenant_chirho(label_chirho: &str) -> GrowthTenantChirho {
    // A tenant root: customer writes (the save's WriteStore door) refuse on the platform root by design.
    let root_chirho = tenant_root_for_test_chirho(label_chirho);
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-secret-value",
    )
    .unwrap()
    .principal_chirho;
    let mut dirs_chirho = deploy_growth_app_chirho(&root_chirho, &owner_chirho, label_chirho);
    dirs_chirho.push(root_chirho.clone());
    let client_chirho =
        oauth_chirho::register_client_chirho(&root_chirho, GROWTH_APP_CHIRHO, &owner_chirho)
            .unwrap();
    let user_credentials_chirho = [0, 1].map(|index_chirho| {
        let secret_chirho = format!("user-secret-value-{index_chirho}");
        let user_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::UserChirho,
            &secret_chirho,
        )
        .unwrap();
        (user_chirho.principal_chirho, secret_chirho)
    });
    let users_chirho = [0, 1].map(|index_chirho| {
        let (principal_chirho, secret_chirho) = &user_credentials_chirho[index_chirho];
        let token_chirho = oauth_chirho::issue_scoped_token_with_rate_limit_chirho(
            &root_chirho,
            principal_chirho,
            secret_chirho,
            &client_chirho.client_id_chirho,
            vec!["invoke_chirho".to_string()],
            Some(oauth_chirho::ScopedTokenRateLimitChirho {
                window_ms_chirho: 60_000,
                // At the ceiling (brick 4a-2): a policy above it is refused at use; no arm here nears it.
                max_invokes_chirho: oauth_chirho::TOKEN_RATE_MAX_INVOKES_CEILING_CHIRHO,
                device_id_chirho: Some(format!("route-growth-{index_chirho}-chirho")),
            }),
        )
        .unwrap();
        let mut headers_chirho = HeaderMap::new();
        headers_chirho.insert(
            AUTHORIZATION,
            format!("Bearer {}", token_chirho.token_chirho)
                .parse()
                .unwrap(),
        );
        headers_chirho
    });
    GrowthTenantChirho {
        root_chirho,
        owner_chirho,
        users_chirho,
        user_credentials_chirho,
        dirs_chirho,
    }
}

/// The tenant's served state, with the abuse gate's budget raised far above the default (60 requests per principal a
/// minute): the arm drives up to 100 saves per principal in seconds, and the gate is not on the history axis.
/// The runtime a counted road runs on: ONE thread, so a detached task the request spawns runs on the counting thread
/// too. A multi-thread runtime could poll that task on any worker, and per-thread counters would miss its work.
pub(super) fn counted_road_runtime_chirho() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

pub(super) fn growth_state_chirho(root_chirho: &Path) -> AppStateChirho {
    let mut state_chirho = app_state_for_root_chirho(root_chirho);
    state_chirho.served_request_abuse_gate_chirho = Arc::new(
        ServedRequestAbuseGateChirho::new_chirho(ServedRequestAbuseLimitsChirho {
            actor_max_requests_chirho: 100_000,
            global_max_requests_chirho: 100_000,
            ..ServedRequestAbuseLimitsChirho::default()
        })
        .unwrap(),
    );
    state_chirho
}

pub(super) async fn response_text_chirho(
    response_chirho: axum::response::Response,
) -> (StatusCode, String) {
    let status_chirho = response_chirho.status();
    let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status_chirho,
        String::from_utf8_lossy(&body_chirho).into_owned(),
    )
}

/// A GET of the view route through the production GET handler.
pub(super) async fn view_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
) -> (StatusCode, String) {
    let uri_chirho: axum::http::Uri =
        format!("/app-chirho/{GROWTH_APP_CHIRHO}/{VIEW_ROUTE_CHIRHO}")
            .parse()
            .unwrap();
    response_text_chirho(
        app_route_get_chirho(
            State(state_chirho.clone()),
            None,
            headers_chirho.clone(),
            AxPath((GROWTH_APP_CHIRHO.to_string(), VIEW_ROUTE_CHIRHO.to_string())),
            axum::extract::OriginalUri(uri_chirho),
        )
        .await,
    )
    .await
}

/// A POST of the save route through the production POST handler (the one the router registers).
pub(super) async fn save_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
    body_chirho: String,
) -> (StatusCode, String) {
    let mut request_chirho = axum::http::Request::builder()
        .method("POST")
        .uri(format!(
            "/app-chirho/{GROWTH_APP_CHIRHO}/{SAVE_ROUTE_CHIRHO}"
        ))
        .body(axum::body::Body::from(body_chirho))
        .unwrap();
    *request_chirho.headers_mut() = headers_chirho.clone();
    response_text_chirho(
        app_route_post_request_chirho(
            State(state_chirho.clone()),
            None,
            headers_chirho.clone(),
            AxPath((GROWTH_APP_CHIRHO.to_string(), SAVE_ROUTE_CHIRHO.to_string())),
            request_chirho,
        )
        .await,
    )
    .await
}

/// The head version a viewer-state response names, read from the rendered page (the render guest is identity).
pub(super) fn head_version_chirho(page_chirho: &str) -> Option<u64> {
    let value_chirho: serde_json::Value = serde_json::from_str(page_chirho)
        .unwrap_or_else(|_| panic!("the page is the viewer-state response: {page_chirho}"));
    value_chirho["current_chirho"]["version_chirho"].as_u64()
}

pub(super) fn write_request_chirho(expected_chirho: Option<u64>, content_chirho: &str) -> String {
    let mut request_chirho = serde_json::json!({
        "schema_chirho": "viewer-state-request-v1-chirho",
        "action_chirho": "write-chirho",
        "key_chirho": STATE_KEY_CHIRHO,
        "value_base64_chirho": BASE64_CHIRHO.encode(content_chirho.as_bytes()),
    });
    if let Some(expected_chirho) = expected_chirho {
        request_chirho["expected_current_version_chirho"] =
            serde_json::Value::from(expected_chirho);
    }
    request_chirho.to_string()
}

/// One save by a user, at the head the user last saw; returns the new head.
pub(super) async fn save_next_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
    head_chirho: Option<u64>,
    content_chirho: &str,
) -> Option<u64> {
    let (status_chirho, page_chirho) = save_chirho(
        state_chirho,
        headers_chirho,
        write_request_chirho(head_chirho, content_chirho),
    )
    .await;
    assert_eq!(
        status_chirho,
        StatusCode::OK,
        "a save is served: {page_chirho}"
    );
    let next_chirho = head_version_chirho(&page_chirho);
    assert!(
        next_chirho > head_chirho,
        "a save advances the head: {head_chirho:?} -> {next_chirho:?}"
    );
    next_chirho
}

/// What one request added to the tenant's logs and stores: PFE's per-request profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct RequestFootprintChirho {
    values_chirho: usize,
    blobs_chirho: usize,
    key_files_chirho: usize,
    volatile_effects_chirho: usize,
    run_intents_chirho: usize,
    runs_chirho: usize,
    effects_chirho: usize,
}

impl RequestFootprintChirho {
    /// The retained records PFE's growth boundary names (#26561): runs, effects, run intents and private values.
    pub(super) fn retained_chirho(&self) -> [usize; 4] {
        [
            self.runs_chirho,
            self.effects_chirho,
            self.run_intents_chirho,
            self.values_chirho,
        ]
    }
}

fn line_count_chirho(path_chirho: &Path) -> usize {
    std::fs::read_to_string(path_chirho)
        .map(|text_chirho| text_chirho.lines().count())
        .unwrap_or(0)
}

/// How many entries a store directory holds. A directory that cannot be read panics rather than counting zero, so a
/// wrong path can never pass as "nothing added".
pub(super) fn entries_chirho(dir_chirho: &Path) -> usize {
    std::fs::read_dir(dir_chirho)
        .unwrap_or_else(|error_chirho| {
            panic!("{} must be readable: {error_chirho}", dir_chirho.display())
        })
        .count()
}

/// How many records the tenant's run-intent log holds: a replay appends none.
pub(super) fn run_intent_line_count_chirho(root_chirho: &Path) -> usize {
    line_count_chirho(&root_chirho.join("run-intents-chirho.jsonl"))
}

pub(super) fn footprint_chirho(root_chirho: &Path) -> RequestFootprintChirho {
    RequestFootprintChirho {
        values_chirho: line_count_chirho(&root_chirho.join("private-dag-values-chirho.jsonl")),
        blobs_chirho: line_count_chirho(&root_chirho.join("privacy-blob-records-chirho.jsonl")),
        key_files_chirho: std::fs::read_dir(root_chirho.join("privacy-keys-chirho"))
            .map(|entries_chirho| entries_chirho.count())
            .unwrap_or(0),
        volatile_effects_chirho: line_count_chirho(
            &root_chirho.join("volatile-effects-chirho.jsonl"),
        ),
        run_intents_chirho: line_count_chirho(&root_chirho.join("run-intents-chirho.jsonl")),
        runs_chirho: entries_chirho(&root_chirho.join("runs-chirho")),
        effects_chirho: entries_chirho(&root_chirho.join("effects-chirho")),
    }
}

pub(super) fn footprint_delta_chirho(
    before_chirho: RequestFootprintChirho,
    after_chirho: RequestFootprintChirho,
) -> RequestFootprintChirho {
    RequestFootprintChirho {
        values_chirho: after_chirho.values_chirho - before_chirho.values_chirho,
        blobs_chirho: after_chirho.blobs_chirho - before_chirho.blobs_chirho,
        key_files_chirho: after_chirho.key_files_chirho - before_chirho.key_files_chirho,
        volatile_effects_chirho: after_chirho.volatile_effects_chirho
            - before_chirho.volatile_effects_chirho,
        run_intents_chirho: after_chirho.run_intents_chirho - before_chirho.run_intents_chirho,
        runs_chirho: after_chirho.runs_chirho - before_chirho.runs_chirho,
        effects_chirho: after_chirho.effects_chirho - before_chirho.effects_chirho,
    }
}

/// The road counters on this thread. A served run executes on the blocking pool (served-overload (ii)); in test builds
/// the served runtime's one blocking hop carries the pool thread's counts back to the awaiting thread, and
/// `counted_road_runtime_chirho` keeps every async hop of the request on this thread. The controls below prove the
/// counters see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RoadCountsChirho {
    pub(super) control_loads_chirho: u64,
    /// Which logs those loads were, by file name.
    pub(super) loaded_logs_chirho: Vec<String>,
    pub(super) reflog_reads_chirho: u64,
    pub(super) blob_chirho: cairn_chirho::privacy_chirho::private_blob_view_metrics_chirho::BlobRoadCountsChirho,
    pub(super) value_chirho: cairn_chirho::dag_private_value_chirho::private_value_view_metrics_chirho::ValueRoadCountsChirho,
    /// The run-intent admission view's work (checkpoint brick S3).
    pub(super) run_intent_chirho: run_intent_road_chirho::RunIntentRoadCountsChirho,
}

pub(super) fn reset_road_chirho() {
    control_loads_chirho::reset_chirho();
    reflog_reads_chirho::reset_chirho();
    blob_road_chirho::reset_chirho();
    value_road_chirho::reset_chirho();
    run_intent_road_chirho::reset_chirho();
}

pub(super) fn road_chirho() -> RoadCountsChirho {
    RoadCountsChirho {
        control_loads_chirho: control_loads_chirho::count_chirho(),
        loaded_logs_chirho: control_loads_chirho::loaded_logs_chirho(),
        reflog_reads_chirho: reflog_reads_chirho::count_chirho(),
        blob_chirho: blob_road_chirho::counts_chirho(),
        value_chirho: value_road_chirho::counts_chirho(),
        run_intent_chirho: run_intent_road_chirho::counts_chirho(),
    }
}

/// The warm road: no control-plane load, no reflog read, and no whole-log read on the blob, value or run-intent road.
/// The identity log: the authenticated road still reloads it on every request (census identity-auth row 1, owned by
/// wave 1 item 2), so the arm RECORDS its loads apart from the app control plane's.
const IDENTITY_LOG_CHIRHO: &str = "identities-chirho.jsonl";

impl RoadCountsChirho {
    /// Whole-log loads of the APP control plane: every counted load except the identity log's.
    pub(super) fn app_control_loads_chirho(&self) -> usize {
        self.loaded_logs_chirho
            .iter()
            .filter(|log_chirho| log_chirho.as_str() != IDENTITY_LOG_CHIRHO)
            .count()
    }

    pub(super) fn identity_loads_chirho(&self) -> usize {
        self.loaded_logs_chirho.len() - self.app_control_loads_chirho()
    }
}

pub(super) fn assert_warm_road_chirho(road_chirho: &RoadCountsChirho, context_chirho: &str) {
    assert_eq!(
        road_chirho.loaded_logs_chirho.len() as u64,
        road_chirho.control_loads_chirho,
        "{context_chirho}: every counted load names its log: {road_chirho:?}"
    );
    assert_eq!(
        (road_chirho.app_control_loads_chirho(), road_chirho.reflog_reads_chirho),
        (0, 0),
        "{context_chirho}: a warm request loads no app control-plane log and reads no reflog: {road_chirho:?}"
    );
    assert_eq!(
        (
            road_chirho.blob_chirho.full_log_loads_chirho,
            road_chirho.value_chirho.full_log_loads_chirho,
            road_chirho.run_intent_chirho.full_log_loads_chirho,
        ),
        (0, 0, 0),
        "{context_chirho}: a warm request reads no whole blob, value or run-intent log: {road_chirho:?}"
    );
}

/// One warm view and one warm save by user 0, after N saves by each user: (view road, save road, view footprint,
/// save footprint). The first view after the saves is the warming view: it is a fresh run (its admission adds intents)
/// and is not measured; the measured view replays it.
pub(super) fn warm_requests_at_chirho(
    saves_chirho: usize,
) -> (
    RoadCountsChirho,
    RoadCountsChirho,
    RequestFootprintChirho,
    RequestFootprintChirho,
) {
    let tenant_chirho = growth_tenant_chirho(&format!("route-growth-{saves_chirho}"));
    let state_chirho = growth_state_chirho(&tenant_chirho.root_chirho);
    let runtime_chirho = counted_road_runtime_chirho();
    runtime_chirho.block_on(async {
        let mut heads_chirho = [None, None];
        for save_index_chirho in 0..saves_chirho {
            for (user_index_chirho, headers_chirho) in tenant_chirho.users_chirho.iter().enumerate()
            {
                heads_chirho[user_index_chirho] = save_next_chirho(
                    &state_chirho,
                    headers_chirho,
                    heads_chirho[user_index_chirho],
                    &format!("page by user {user_index_chirho}, save {save_index_chirho}"),
                )
                .await;
            }
        }
        let user_chirho = &tenant_chirho.users_chirho[0];
        let (status_chirho, page_chirho) = view_chirho(&state_chirho, user_chirho).await;
        assert_eq!(
            status_chirho,
            StatusCode::OK,
            "the warming view is served: {page_chirho}"
        );
        assert_eq!(
            head_version_chirho(&page_chirho),
            heads_chirho[0],
            "the view shows the user's own head"
        );

        let before_view_chirho = footprint_chirho(&tenant_chirho.root_chirho);
        reset_road_chirho();
        let (status_chirho, page_chirho) = view_chirho(&state_chirho, user_chirho).await;
        let view_road_chirho = road_chirho();
        assert_eq!(
            status_chirho,
            StatusCode::OK,
            "the measured view is served: {page_chirho}"
        );
        let view_footprint_chirho = footprint_delta_chirho(
            before_view_chirho,
            footprint_chirho(&tenant_chirho.root_chirho),
        );

        let before_save_chirho = footprint_chirho(&tenant_chirho.root_chirho);
        reset_road_chirho();
        save_next_chirho(
            &state_chirho,
            user_chirho,
            heads_chirho[0],
            "the measured save",
        )
        .await;
        let save_road_chirho = road_chirho();
        let save_footprint_chirho = footprint_delta_chirho(
            before_save_chirho,
            footprint_chirho(&tenant_chirho.root_chirho),
        );
        (
            view_road_chirho,
            save_road_chirho,
            view_footprint_chirho,
            save_footprint_chirho,
        )
    })
}

/// Replace a log with a byte-identical copy under a new inode: the next lookup must rebuild that log's view.
pub(super) fn swap_inode_chirho(path_chirho: &Path) {
    let bytes_chirho = std::fs::read(path_chirho).unwrap();
    let swap_chirho = path_chirho.with_extension("swap-chirho");
    std::fs::write(&swap_chirho, &bytes_chirho).unwrap();
    std::fs::rename(&swap_chirho, path_chirho).unwrap();
}
