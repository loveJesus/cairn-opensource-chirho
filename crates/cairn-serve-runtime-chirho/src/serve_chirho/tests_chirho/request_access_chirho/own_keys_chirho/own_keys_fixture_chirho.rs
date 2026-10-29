// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The K3 fixture: an app-wide signed-in app whose `account` route reads the viewer's own keys through a blessed
//! read-store card at `own-keys-chirho/` (request, build, door, render, every edge private to her), deployed from its
//! tree-built manifest on a tenant root and served through the production handlers, with users who sign in and hold
//! legacy keys on it.
//! Workflow: the owner's keys page (K3),
//! `spec-chirho/workflows-chirho/identity-auth-chirho/own-keys-page-chirho.md`.

use super::app_route_fixture_chirho::{
    host_ready_chirho, own_keys_dag_chirho, response_text_chirho, tmp_dir_chirho,
    viewer_state_dag_chirho,
};
use super::*;
use cairn_tree_build_chirho::check_chirho::check_app_tree_chirho;
use cairn_tree_build_chirho::emit_chirho::{
    emit_manifest_chirho, AppDescriptorChirho, AppRootChirho, AppRouteChirho,
};
use cairn_tree_build_chirho::tree_chirho::walk_app_tree_chirho;
use std::path::PathBuf;

pub(super) const ACCOUNT_APP_CHIRHO: &str = "accountapp";
pub(super) const ACCOUNT_ROUTE_CHIRHO: &str = "account";

fn account_descriptor_chirho(owner_chirho: &str) -> AppDescriptorChirho {
    AppDescriptorChirho {
        app_chirho: ACCOUNT_APP_CHIRHO.to_string(),
        owner_chirho: owner_chirho.to_string(),
        package_chirho: "accountapp-chirho".to_string(),
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
        route_chirho: vec![AppRouteChirho {
            dag_chirho: "account_chirho".to_string(),
            input_mode_chirho: "private-blob-ref".to_string(),
            subject_chirho: Some("request-user-chirho".to_string()),
            safe_metadata_chirho: vec![],
            request_body_policy_chirho: None,
            route_chirho: ACCOUNT_ROUTE_CHIRHO.to_string(),
            key_access_chirho: None,
            key_action_chirho: None,
            key_resources_chirho: Vec::new(),
        }],
        internal_module_chirho: vec![],
        asset_chirho: vec![],
    }
}

/// The tenant: the account app, its oauth client, and users with their credentials.
pub(super) struct AccountTenantChirho {
    pub(super) root_chirho: PathBuf,
    client_id_chirho: String,
    users_chirho: Vec<(String, String)>,
    dirs_chirho: Vec<PathBuf>,
}

impl Drop for AccountTenantChirho {
    fn drop(&mut self) {
        for dir_chirho in &self.dirs_chirho {
            let _ = std::fs::remove_dir_all(dir_chirho);
        }
    }
}

impl AccountTenantChirho {
    /// A tenant with the account app deployed and `user_count_chirho` users.
    pub(super) fn new_chirho(label_chirho: &str, user_count_chirho: usize) -> Self {
        let root_chirho = tenant_root_for_test_chirho(label_chirho);
        let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
            "owner-secret-value",
        )
        .unwrap()
        .principal_chirho;
        let tree_chirho = tmp_dir_chirho(&format!("{label_chirho}-account-tree"));
        let guests_chirho = tmp_dir_chirho(&format!("{label_chirho}-account-guests"));
        std::fs::create_dir_all(tree_chirho.join("src")).unwrap();
        viewer_state_dag_chirho(
            &tree_chirho,
            "home_chirho",
            "build_home_chirho",
            "read_home_chirho",
            "read-store",
            "render_home_chirho",
        );
        own_keys_dag_chirho(
            &tree_chirho,
            "account_chirho",
            "build_keys_chirho",
            "read_keys_chirho",
            "render_keys_chirho",
        );
        let walked_chirho = walk_app_tree_chirho(&tree_chirho);
        let diagnostics_chirho = check_app_tree_chirho(&walked_chirho);
        assert!(diagnostics_chirho.is_empty(), "{diagnostics_chirho:?}");
        let emitted_chirho =
            emit_manifest_chirho(&walked_chirho, &account_descriptor_chirho(&owner_chirho))
                .unwrap();
        let manifest_chirho: cairn_chirho::app_source_manifest_chirho::AppSourceManifestChirho =
            serde_json::from_value(host_ready_chirho(emitted_chirho, &guests_chirho))
                .expect("the emitted manifest parses");
        cairn_chirho::app_source_manifest_chirho::deploy_app_source_manifest_chirho(
            &root_chirho,
            &guests_chirho,
            &manifest_chirho,
        )
        .expect("the account app deploys");
        let client_id_chirho =
            oauth_chirho::register_client_chirho(&root_chirho, ACCOUNT_APP_CHIRHO, &owner_chirho)
                .unwrap()
                .client_id_chirho;
        let users_chirho = (0..user_count_chirho)
            .map(|index_chirho| {
                let secret_chirho = format!("account-user-secret-{index_chirho}");
                let principal_chirho = identity_chirho::register_identity_with_credential_chirho(
                    &root_chirho,
                    identity_chirho::PrincipalKindChirho::UserChirho,
                    &secret_chirho,
                )
                .unwrap()
                .principal_chirho;
                (principal_chirho, secret_chirho)
            })
            .collect();
        Self {
            dirs_chirho: vec![root_chirho.clone(), tree_chirho, guests_chirho],
            root_chirho,
            client_id_chirho,
            users_chirho,
        }
    }

    /// A legacy key on the account app for user `index_chirho`.
    pub(super) fn legacy_key_chirho(
        &self,
        index_chirho: usize,
    ) -> oauth_chirho::ScopedTokenIssueChirho {
        let (principal_chirho, secret_chirho) = &self.users_chirho[index_chirho];
        oauth_chirho::issue_scoped_token_with_rate_limit_chirho(
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
        )
        .expect("the legacy key issues")
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

    /// A key's request, as a bearer header.
    pub(super) fn bearer_chirho(token_chirho: &str) -> HeaderMap {
        let mut headers_chirho = HeaderMap::new();
        headers_chirho.insert(
            AUTHORIZATION,
            format!("Bearer {token_chirho}").parse().unwrap(),
        );
        headers_chirho
    }

    /// The tenant's served state with the abuse gate's budget raised (it is not on the axis these arms measure).
    pub(super) fn state_chirho(&self) -> AppStateChirho {
        super::app_route_fixture_chirho::growth_state_chirho(&self.root_chirho)
    }

    /// A GET of the account route through the production GET handler.
    pub(super) async fn get_account_chirho(
        &self,
        state_chirho: &AppStateChirho,
        headers_chirho: &HeaderMap,
    ) -> (StatusCode, String) {
        let uri_chirho: axum::http::Uri =
            format!("/app-chirho/{ACCOUNT_APP_CHIRHO}/{ACCOUNT_ROUTE_CHIRHO}")
                .parse()
                .unwrap();
        response_text_chirho(
            app_route_get_chirho(
                State(state_chirho.clone()),
                None,
                headers_chirho.clone(),
                AxPath((
                    ACCOUNT_APP_CHIRHO.to_string(),
                    ACCOUNT_ROUTE_CHIRHO.to_string(),
                )),
                axum::extract::OriginalUri(uri_chirho),
            )
            .await,
        )
        .await
    }
}
