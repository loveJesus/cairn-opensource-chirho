// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The world K4's token and management arms share: a root with an app opened before its client registered (so a
//! connection client), an app that opens nothing (so a legacy client), one user, and the keys each issues.

use super::super::{
    issue_limited_key_chirho, issue_scoped_token_with_rate_limit_chirho,
    public_default_rate_limit_chirho, ScopedTokenIssueChirho,
};
use super::*;
use crate::model_chirho::{CapabilityChirho, DagChirho, HashChirho, NodeDefChirho};
use cairn_model_app_chirho::AppKeyAuthorityRouteChirho;
use identity_chirho::PrincipalKindChirho;
use std::sync::atomic::{AtomicU64, Ordering};

/// Opened before its client registers, so its client is a connection client.
pub(super) const OPENED_APP_CHIRHO: &str = "connected";
/// Opens nothing, so its client is a legacy client.
pub(super) const PLAIN_APP_CHIRHO: &str = "plainapp";
pub(super) const SECRET_CHIRHO: &str = "k4-token-secret-chirho";
pub(super) const LEGACY_TOKENS_CHIRHO: &str = "scoped-tokens-chirho.jsonl";
pub(super) const CONNECTION_TOKENS_CHIRHO: &str = "connection-tokens-chirho.jsonl";
pub(super) const LEGACY_USES_CHIRHO: &str = "scoped-token-uses-chirho.jsonl";
pub(super) const CONNECTION_USES_CHIRHO: &str = "connection-token-uses-chirho.jsonl";

static NEXT_ROOT_CHIRHO: AtomicU64 = AtomicU64::new(0);

pub(super) fn own_root_chirho(label_chirho: &str) -> PathBuf {
    let number_chirho = NEXT_ROOT_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-k4-tokens-{label_chirho}-{}-{number_chirho}-chirho",
        std::process::id()
    ));
    std::fs::create_dir(&root_chirho).unwrap();
    root_chirho
}

/// A copy of the root at a fresh path, so no view has been loaded for it: its first lookup is a first load. Each copy's
/// path is new: a path already present would make `cp` nest the copy inside it.
pub(super) fn fresh_copy_chirho(root_chirho: &Path) -> PathBuf {
    let number_chirho = NEXT_ROOT_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let copy_chirho = PathBuf::from(format!(
        "{}-copy-{number_chirho}-chirho",
        root_chirho.display()
    ));
    assert!(!copy_chirho.exists(), "a fresh copy's path is new");
    assert!(std::process::Command::new("cp")
        .arg("-Rp")
        .arg(root_chirho)
        .arg(&copy_chirho)
        .status()
        .unwrap()
        .success());
    copy_chirho
}

/// Deploy `app_chirho` with a home and a view route, each a viewer-state read; returns the view's DAG.
pub(super) fn deploy_app_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> HashChirho {
    let dag_chirho = |label_chirho: &str| {
        let wasm_chirho = crate::cas_chirho::add_chirho(
            root_chirho,
            format!("{app_chirho}-{label_chirho}").as_bytes(),
        )
        .unwrap();
        let node_chirho = crate::store_chirho::put_object_chirho(
            root_chirho,
            &NodeDefChirho {
                name_chirho: label_chirho.to_string(),
                impl_wasm_chirho: wasm_chirho,
                entry_chirho: "run_chirho".to_string(),
                capabilities_chirho: vec![CapabilityChirho::ReadStoreChirho {
                    prefix_chirho: "viewer-state-chirho/".to_string(),
                }],
                ..Default::default()
            },
        )
        .unwrap();
        crate::store_chirho::put_object_chirho(
            root_chirho,
            &DagChirho {
                nodes_chirho: vec![node_chirho],
                edges_chirho: Vec::new(),
            },
        )
        .unwrap()
    };
    let home_chirho = dag_chirho("home");
    let view_chirho = dag_chirho("view");
    app_chirho::deploy_app_chirho(root_chirho, app_chirho, home_chirho, owner_chirho).unwrap();
    app_chirho::deploy_app_route_chirho(
        root_chirho,
        app_chirho,
        "view",
        view_chirho.clone(),
        owner_chirho,
    )
    .unwrap();
    view_chirho
}

pub(super) fn view_opening_chirho(view_chirho: &HashChirho) -> Vec<AppKeyAuthorityRouteChirho> {
    vec![AppKeyAuthorityRouteChirho {
        route_chirho: "view".to_string(),
        action_chirho: "page-read-chirho".to_string(),
        dag_chirho: view_chirho.clone(),
        resources_chirho: vec!["page-document-chirho".to_string()],
    }]
}

pub(super) fn page_read_chirho() -> Vec<String> {
    vec!["page-read-chirho".to_string()]
}

/// A root with an opened app and its connection client, an unopened app and its legacy client, and one user.
pub(super) struct TokenWorldChirho {
    pub(super) root_chirho: PathBuf,
    pub(super) user_chirho: String,
    pub(super) connection_client_chirho: OauthClientRecordChirho,
    pub(super) legacy_client_chirho: OauthClientRecordChirho,
}

pub(super) fn world_chirho(label_chirho: &str) -> TokenWorldChirho {
    let root_chirho = own_root_chirho(label_chirho);
    let owner_chirho =
        identity_chirho::register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
            .unwrap()
            .principal_chirho;
    let opened_view_chirho = deploy_app_chirho(&root_chirho, OPENED_APP_CHIRHO, &owner_chirho);
    deploy_app_chirho(&root_chirho, PLAIN_APP_CHIRHO, &owner_chirho);
    crate::app_manifest_chirho::open_app_to_limited_keys_chirho(
        &root_chirho,
        OPENED_APP_CHIRHO,
        &owner_chirho,
        view_opening_chirho(&opened_view_chirho),
    )
    .unwrap();
    let (connection_client_chirho, connection_store_chirho) =
        register_client_in_store_chirho(&root_chirho, OPENED_APP_CHIRHO, &owner_chirho).unwrap();
    let (legacy_client_chirho, legacy_store_chirho) =
        register_client_in_store_chirho(&root_chirho, PLAIN_APP_CHIRHO, &owner_chirho).unwrap();
    assert_eq!(
        (connection_store_chirho, legacy_store_chirho),
        (
            KeyStoreChirho::ConnectionChirho,
            KeyStoreChirho::LegacyChirho
        )
    );
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        SECRET_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    TokenWorldChirho {
        root_chirho,
        user_chirho,
        connection_client_chirho,
        legacy_client_chirho,
    }
}

impl TokenWorldChirho {
    pub(super) fn connection_key_chirho(&self) -> Result<ScopedTokenIssueChirho> {
        issue_limited_key_chirho(
            &self.root_chirho,
            &self.user_chirho,
            SECRET_CHIRHO,
            &self.connection_client_chirho.client_id_chirho,
            &page_read_chirho(),
            None,
        )
    }

    pub(super) fn legacy_key_chirho(&self) -> Result<ScopedTokenIssueChirho> {
        issue_scoped_token_with_rate_limit_chirho(
            &self.root_chirho,
            &self.user_chirho,
            SECRET_CHIRHO,
            &self.legacy_client_chirho.client_id_chirho,
            Vec::new(),
            Some(public_default_rate_limit_chirho()),
        )
    }

    pub(super) fn lines_chirho(&self, name_chirho: &str) -> usize {
        std::fs::read_to_string(self.root_chirho.join(name_chirho))
            .map(|text_chirho| text_chirho.lines().count())
            .unwrap_or(0)
    }

    pub(super) fn token_lines_chirho(&self) -> (usize, usize) {
        (
            self.lines_chirho(LEGACY_TOKENS_CHIRHO),
            self.lines_chirho(CONNECTION_TOKENS_CHIRHO),
        )
    }

    pub(super) fn use_lines_chirho(&self) -> (usize, usize) {
        (
            self.lines_chirho(LEGACY_USES_CHIRHO),
            self.lines_chirho(CONNECTION_USES_CHIRHO),
        )
    }
}

impl Drop for TokenWorldChirho {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root_chirho);
    }
}

pub(super) fn refusal_text_chirho<T: std::fmt::Debug>(outcome_chirho: Result<T>) -> String {
    format!("{:#}", outcome_chirho.unwrap_err())
}
