// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The K1 fixture: the growth arms' viewer-state app (a view GET and a save POST over one logical key, every edge
//! private to the requesting user) deployed under its own name on a tenant root, with its openings to limited keys
//! set per deploy, served through the production handlers.
//!
//! A deploy takes the tree-built manifest and an edit: the edit can open routes (as `app-chirho.toml` would, lowered
//! by tree-build), point a route at another route's module (its capabilities change, its name does not), or add a
//! route. Keys are issued through the real issuance roads: limited keys by named actions, legacy keys with the default
//! scope.

use super::app_route_fixture_chirho::{
    host_ready_chirho, response_text_chirho, tmp_dir_chirho, viewer_state_dag_chirho,
};
use super::*;
use cairn_tree_build_chirho::check_chirho::check_app_tree_chirho;
use cairn_tree_build_chirho::emit_chirho::{
    emit_manifest_chirho, AppDescriptorChirho, AppRootChirho, AppRouteChirho,
};
use cairn_tree_build_chirho::tree_chirho::walk_app_tree_chirho;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(super) const KEYED_APP_CHIRHO: &str = "keyedapp";
pub(super) const VIEW_ROUTE_CHIRHO: &str = "view";
pub(super) const SAVE_ROUTE_CHIRHO: &str = "save";
pub(super) const PAGE_READ_CHIRHO: &str = "page-read-chirho";
pub(super) const PAGE_SAVE_CHIRHO: &str = "page-save-chirho";

fn keyed_route_chirho(
    dag_chirho: &str,
    route_chirho: &str,
    accepts_body_chirho: bool,
    opening_chirho: Option<(&str, &[&str])>,
) -> AppRouteChirho {
    AppRouteChirho {
        dag_chirho: dag_chirho.to_string(),
        input_mode_chirho: "private-blob-ref".to_string(),
        subject_chirho: Some("request-user-chirho".to_string()),
        safe_metadata_chirho: vec![],
        request_body_policy_chirho: accepts_body_chirho.then(|| "accept-body".to_string()),
        route_chirho: route_chirho.to_string(),
        key_access_chirho: opening_chirho.map(|_| "open".to_string()),
        key_action_chirho: opening_chirho.map(|(action_chirho, _)| action_chirho.to_string()),
        key_resources_chirho: opening_chirho
            .map(|(_, resources_chirho)| resources_chirho.iter().map(|r| r.to_string()).collect())
            .unwrap_or_default(),
    }
}

/// The app's openings for one deploy, as `app-chirho.toml` would declare them.
#[derive(Clone, Copy)]
pub(super) struct OpeningsChirho<'a> {
    pub(super) view_chirho: Option<(&'a str, &'a [&'a str])>,
    pub(super) save_chirho: Option<(&'a str, &'a [&'a str])>,
}

impl OpeningsChirho<'static> {
    /// Nothing opened: a legacy-mode app.
    pub(super) const NONE_CHIRHO: Self = Self {
        view_chirho: None,
        save_chirho: None,
    };
    /// The product's first cut: the view for page-read, the save for page-save, both over the one page key.
    pub(super) const PAGE_CHIRHO: Self = Self {
        view_chirho: Some((
            PAGE_READ_CHIRHO,
            &[super::app_route_fixture_chirho::STATE_KEY_CHIRHO],
        )),
        save_chirho: Some((
            PAGE_SAVE_CHIRHO,
            &[super::app_route_fixture_chirho::STATE_KEY_CHIRHO],
        )),
    };
}

fn keyed_descriptor_chirho(
    owner_chirho: &str,
    openings_chirho: OpeningsChirho<'_>,
) -> AppDescriptorChirho {
    AppDescriptorChirho {
        app_chirho: KEYED_APP_CHIRHO.to_string(),
        owner_chirho: owner_chirho.to_string(),
        package_chirho: "keyedapp-chirho".to_string(),
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
            keyed_route_chirho(
                "view_chirho",
                VIEW_ROUTE_CHIRHO,
                false,
                openings_chirho.view_chirho,
            ),
            keyed_route_chirho(
                "save_chirho",
                SAVE_ROUTE_CHIRHO,
                true,
                openings_chirho.save_chirho,
            ),
        ],
        internal_module_chirho: vec![],
        asset_chirho: vec![],
    }
}

/// The tenant: the keyed app, its oauth client, and users with their credentials.
pub(super) struct KeyedTenantChirho {
    pub(super) root_chirho: PathBuf,
    pub(super) owner_chirho: String,
    pub(super) client_id_chirho: String,
    users_chirho: Vec<(String, String)>,
    tree_chirho: PathBuf,
    guests_chirho: PathBuf,
    dirs_chirho: Vec<PathBuf>,
}

impl Drop for KeyedTenantChirho {
    fn drop(&mut self) {
        for dir_chirho in &self.dirs_chirho {
            let _ = std::fs::remove_dir_all(dir_chirho);
        }
    }
}

impl KeyedTenantChirho {
    /// A tenant with the keyed app deployed with `openings_chirho`, and `user_count_chirho` users.
    pub(super) fn new_chirho(
        label_chirho: &str,
        openings_chirho: OpeningsChirho<'_>,
        user_count_chirho: usize,
    ) -> Self {
        Self::new_with_chirho(label_chirho, openings_chirho, user_count_chirho, |_| {})
    }

    /// The same, with `edit_chirho` applied to the FIRST deploy's manifest: some policies (a private input mode) are
    /// sticky, so a later redeploy cannot stand in for them.
    pub(super) fn new_with_chirho(
        label_chirho: &str,
        openings_chirho: OpeningsChirho<'_>,
        user_count_chirho: usize,
        edit_chirho: impl FnOnce(&mut serde_json::Value),
    ) -> Self {
        let root_chirho = tenant_root_for_test_chirho(label_chirho);
        let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
            "owner-secret-value",
        )
        .unwrap()
        .principal_chirho;
        let tree_chirho = tmp_dir_chirho(&format!("{label_chirho}-keyed-tree"));
        let guests_chirho = tmp_dir_chirho(&format!("{label_chirho}-keyed-guests"));
        std::fs::create_dir_all(tree_chirho.join("src")).unwrap();
        for (dag_chirho, build_chirho, door_chirho, contract_chirho, render_chirho) in [
            (
                "home_chirho",
                "build_home_chirho",
                "read_home_chirho",
                "read-store",
                "render_home_chirho",
            ),
            (
                "view_chirho",
                "build_read_chirho",
                "read_state_chirho",
                "read-store",
                "render_view_chirho",
            ),
            (
                "save_chirho",
                "build_write_chirho",
                "write_state_chirho",
                "write-store",
                "render_save_chirho",
            ),
        ] {
            viewer_state_dag_chirho(
                &tree_chirho,
                dag_chirho,
                build_chirho,
                door_chirho,
                contract_chirho,
                render_chirho,
            );
        }
        let mut tenant_chirho = Self {
            dirs_chirho: vec![
                root_chirho.clone(),
                tree_chirho.clone(),
                guests_chirho.clone(),
            ],
            root_chirho,
            owner_chirho,
            client_id_chirho: String::new(),
            users_chirho: Vec::new(),
            tree_chirho,
            guests_chirho,
        };
        tenant_chirho.deploy_chirho(openings_chirho, edit_chirho);
        tenant_chirho.client_id_chirho = oauth_chirho::register_client_chirho(
            &tenant_chirho.root_chirho,
            KEYED_APP_CHIRHO,
            &tenant_chirho.owner_chirho,
        )
        .unwrap()
        .client_id_chirho;
        for index_chirho in 0..user_count_chirho {
            let secret_chirho = format!("keyed-user-secret-{index_chirho}");
            let principal_chirho = identity_chirho::register_identity_with_credential_chirho(
                &tenant_chirho.root_chirho,
                identity_chirho::PrincipalKindChirho::UserChirho,
                &secret_chirho,
            )
            .unwrap()
            .principal_chirho;
            tenant_chirho
                .users_chirho
                .push((principal_chirho, secret_chirho));
        }
        tenant_chirho
    }

    /// Deploy the keyed app with `openings_chirho`, after `edit_chirho` has changed the emitted manifest.
    pub(super) fn deploy_chirho(
        &self,
        openings_chirho: OpeningsChirho<'_>,
        edit_chirho: impl FnOnce(&mut serde_json::Value),
    ) {
        let tree_chirho = walk_app_tree_chirho(&self.tree_chirho);
        assert!(check_app_tree_chirho(&tree_chirho).is_empty());
        let mut emitted_chirho = emit_manifest_chirho(
            &tree_chirho,
            &keyed_descriptor_chirho(&self.owner_chirho, openings_chirho),
        )
        .unwrap();
        edit_chirho(&mut emitted_chirho);
        let manifest_chirho: cairn_chirho::app_source_manifest_chirho::AppSourceManifestChirho =
            serde_json::from_value(host_ready_chirho(emitted_chirho, &self.guests_chirho))
                .expect("the emitted manifest parses");
        cairn_chirho::app_source_manifest_chirho::deploy_app_source_manifest_chirho(
            &self.root_chirho,
            &self.guests_chirho,
            &manifest_chirho,
        )
        .expect("the keyed app deploys");
    }

    /// The deploy that may refuse: its result instead of a panic.
    pub(super) fn try_deploy_chirho(
        &self,
        openings_chirho: OpeningsChirho<'_>,
        edit_chirho: impl FnOnce(&mut serde_json::Value),
    ) -> anyhow::Result<()> {
        let tree_chirho = walk_app_tree_chirho(&self.tree_chirho);
        let mut emitted_chirho = emit_manifest_chirho(
            &tree_chirho,
            &keyed_descriptor_chirho(&self.owner_chirho, openings_chirho),
        )
        .map_err(|error_chirho| anyhow::anyhow!(error_chirho))?;
        edit_chirho(&mut emitted_chirho);
        let manifest_chirho: cairn_chirho::app_source_manifest_chirho::AppSourceManifestChirho =
            serde_json::from_value(host_ready_chirho(emitted_chirho, &self.guests_chirho))?;
        cairn_chirho::app_source_manifest_chirho::deploy_app_source_manifest_chirho(
            &self.root_chirho,
            &self.guests_chirho,
            &manifest_chirho,
        )?;
        Ok(())
    }

    /// A limited key for user `index_chirho` holding `actions_chirho`, as a bearer header.
    pub(super) fn limited_bearer_chirho(
        &self,
        index_chirho: usize,
        actions_chirho: &[&str],
    ) -> HeaderMap {
        let (principal_chirho, secret_chirho) = &self.users_chirho[index_chirho];
        let issue_chirho = oauth_chirho::issue_limited_key_chirho(
            &self.root_chirho,
            principal_chirho,
            secret_chirho,
            &self.client_id_chirho,
            &actions_chirho
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>(),
            None,
        )
        .expect("the limited key issues");
        bearer_headers_chirho(&issue_chirho.token_chirho)
    }

    /// A legacy key for user `index_chirho` (the default scope), or the issuance refusal.
    pub(super) fn try_legacy_bearer_chirho(
        &self,
        index_chirho: usize,
    ) -> anyhow::Result<HeaderMap> {
        let (principal_chirho, secret_chirho) = &self.users_chirho[index_chirho];
        let issue_chirho = oauth_chirho::issue_scoped_token_with_rate_limit_chirho(
            &self.root_chirho,
            principal_chirho,
            secret_chirho,
            &self.client_id_chirho,
            Vec::new(),
            Some(oauth_chirho::ScopedTokenRateLimitChirho {
                window_ms_chirho: 60_000,
                max_invokes_chirho: oauth_chirho::TOKEN_RATE_MAX_INVOKES_CEILING_CHIRHO,
                device_id_chirho: None,
            }),
        )?;
        Ok(bearer_headers_chirho(&issue_chirho.token_chirho))
    }

    /// A signed-in browser session for user `index_chirho`, as a cookie header.
    pub(super) fn cookie_chirho(&self, index_chirho: usize) -> HeaderMap {
        let (principal_chirho, secret_chirho) = &self.users_chirho[index_chirho];
        let login_chirho = identity_chirho::login_identity_with_credential_chirho(
            &self.root_chirho,
            principal_chirho,
            secret_chirho,
        )
        .unwrap();
        let mut headers_chirho = HeaderMap::new();
        headers_chirho.insert(
            axum::http::header::COOKIE,
            format!(
                "cairn_session_chirho={principal_chirho}:{}",
                login_chirho.token_chirho
            )
            .parse()
            .unwrap(),
        );
        headers_chirho
    }

    /// User `index_chirho`'s principal and credential, for a road this process does not serve (a twin's sign-in).
    pub(super) fn user_chirho(&self, index_chirho: usize) -> (&str, &str) {
        let (principal_chirho, secret_chirho) = &self.users_chirho[index_chirho];
        (principal_chirho, secret_chirho)
    }

    /// The tenant's served state with the abuse gate's budget raised (it is not on the axis these arms measure).
    pub(super) fn state_chirho(&self) -> AppStateChirho {
        super::app_route_fixture_chirho::growth_state_chirho(&self.root_chirho)
    }
}

fn bearer_headers_chirho(token_chirho: &str) -> HeaderMap {
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {token_chirho}").parse().unwrap(),
    );
    headers_chirho
}

/// The emitted manifest's route entry named `route_chirho`.
pub(super) fn route_entry_chirho<'a>(
    manifest_chirho: &'a mut serde_json::Value,
    route_chirho: &str,
) -> &'a mut serde_json::Value {
    manifest_chirho["deploy_chirho"]["routes_chirho"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry_chirho| entry_chirho["route_chirho"] == route_chirho)
        .unwrap_or_else(|| panic!("the manifest has a route '{route_chirho}'"))
}

/// A GET of a named route of the keyed app through the production GET handler.
pub(super) async fn get_route_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
    route_chirho: &str,
) -> (StatusCode, String) {
    let uri_chirho: axum::http::Uri = format!("/app-chirho/{KEYED_APP_CHIRHO}/{route_chirho}")
        .parse()
        .unwrap();
    response_text_chirho(
        app_route_get_chirho(
            State(state_chirho.clone()),
            None,
            headers_chirho.clone(),
            AxPath((KEYED_APP_CHIRHO.to_string(), route_chirho.to_string())),
            axum::extract::OriginalUri(uri_chirho),
        )
        .await,
    )
    .await
}

/// A POST of a named route of the keyed app through the production POST handler.
pub(super) async fn post_route_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
    route_chirho: &str,
    body_chirho: String,
) -> (StatusCode, String) {
    let mut request_chirho = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/app-chirho/{KEYED_APP_CHIRHO}/{route_chirho}"))
        .body(axum::body::Body::from(body_chirho))
        .unwrap();
    *request_chirho.headers_mut() = headers_chirho.clone();
    response_text_chirho(
        app_route_post_request_chirho(
            State(state_chirho.clone()),
            None,
            headers_chirho.clone(),
            AxPath((KEYED_APP_CHIRHO.to_string(), route_chirho.to_string())),
            request_chirho,
        )
        .await,
    )
    .await
}

/// A GET of the keyed app's root through the production root handler.
pub(super) async fn get_root_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
) -> (StatusCode, String) {
    let uri_chirho: axum::http::Uri = format!("/app-chirho/{KEYED_APP_CHIRHO}/").parse().unwrap();
    response_text_chirho(
        app_get_chirho(
            State(state_chirho.clone()),
            None,
            headers_chirho.clone(),
            uri_chirho,
            AxPath(KEYED_APP_CHIRHO.to_string()),
        )
        .await,
    )
    .await
}

pub(super) fn bearer_chirho(token_chirho: &str) -> String {
    format!("Bearer {token_chirho}")
}

/// The successor's own router serving `root_chirho` on a real port while `probe_chirho` runs.
pub(super) fn with_successor_served_chirho<T>(
    root_chirho: &Path,
    probe_chirho: impl FnOnce(&str) -> T,
) -> T {
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.to_path_buf();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let result_chirho = probe_chirho(&addr_chirho);
        server_chirho.abort();
        result_chirho
    })
}

/// One raw HTTP request: its status and body.
pub(super) fn probe_chirho(
    addr_chirho: &str,
    method_chirho: &str,
    path_chirho: &str,
    headers_chirho: &[(&str, &str)],
    body_chirho: &[u8],
) -> (u16, String) {
    let response_chirho = http_request_for_smoke_chirho(
        addr_chirho,
        method_chirho,
        path_chirho,
        headers_chirho,
        body_chirho,
    );
    (
        response_chirho.status_chirho,
        http_body_text_chirho(&response_chirho),
    )
}

/// Every file under `root_chirho` with its blake3: the whole durable state a request could change.
pub(super) fn root_snapshot_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, String> {
    let mut snapshot_chirho = BTreeMap::new();
    let mut pending_chirho = vec![root_chirho.to_path_buf()];
    while let Some(dir_chirho) = pending_chirho.pop() {
        for entry_chirho in std::fs::read_dir(&dir_chirho).unwrap() {
            let path_chirho = entry_chirho.unwrap().path();
            if path_chirho.is_dir() {
                pending_chirho.push(path_chirho);
            } else {
                let bytes_chirho = std::fs::read(&path_chirho).unwrap();
                snapshot_chirho.insert(
                    path_chirho.strip_prefix(root_chirho).unwrap().to_path_buf(),
                    blake3::hash(&bytes_chirho).to_hex().to_string(),
                );
            }
        }
    }
    snapshot_chirho
}

/// The number of key uses recorded, across both stores' use logs: a key's uses are in its own store's log (K4), so a
/// tenant whose client registered after its app opened records its uses in the connection use log.
pub(super) fn token_use_count_chirho(root_chirho: &Path) -> usize {
    [
        "scoped-token-uses-chirho.jsonl",
        "connection-token-uses-chirho.jsonl",
    ]
    .iter()
    .map(|name_chirho| {
        std::fs::read_to_string(root_chirho.join(name_chirho))
            .map(|text_chirho| {
                text_chirho
                    .lines()
                    .filter(|line_chirho| !line_chirho.trim().is_empty())
                    .count()
            })
            .unwrap_or(0)
    })
    .sum::<usize>()
}

/// The fixed identity line of a refusal body.
pub(super) fn identity_line_chirho(body_chirho: &str) -> &str {
    body_chirho.lines().next().unwrap_or_default()
}
