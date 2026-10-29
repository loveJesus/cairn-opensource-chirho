// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_model_app_chirho::{AppRouteActionChirho, APP_ROUTE_AUTHORITY_STATE_SCHEMA_CHIRHO};
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

struct FakeRoutePortChirho {
    verified_chirho: RefCell<Vec<AppRouteRecordChirho>>,
}

impl AppRouteAuthorityPortChirho for FakeRoutePortChirho {
    fn verified_app_route_records_chirho(
        &self,
        _root_chirho: &Path,
    ) -> Result<Vec<AppRouteRecordChirho>> {
        Ok(self.verified_chirho.borrow().clone())
    }

    fn validate_app_route_deploy_evidence_chirho(
        &self,
        _root_chirho: &Path,
        _state_chirho: &AppRouteAuthorityStateChirho,
    ) -> Result<()> {
        Ok(())
    }

    fn sign_app_route_record_chirho(
        &self,
        _root_chirho: &Path,
        _record_chirho: &AppRouteRecordChirho,
    ) -> Result<String> {
        Ok("root-port-signature-chirho".to_string())
    }

    fn sign_app_route_record_with_key_possession_chirho(
        &self,
        _root_chirho: &Path,
        _record_chirho: &AppRouteRecordChirho,
    ) -> Result<(String, String)> {
        Ok((
            "root-port-key-chirho".to_string(),
            "root-port-signature-chirho".to_string(),
        ))
    }

    fn current_root_signing_key_id_chirho(&self, _root_chirho: &Path) -> Result<String> {
        Ok("root-port-key-chirho".to_string())
    }

    fn append_signed_app_route_undeploy_record_unlocked_chirho(
        &self,
        _root_chirho: &Path,
        _app_chirho: &str,
        _route_chirho: &str,
        _owner_principal_chirho: &str,
    ) -> Result<AppRouteRecordChirho> {
        bail!("fake route port does not append undeploy rows")
    }
}

fn temp_root_chirho() -> PathBuf {
    static NEXT_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-app-control-test-{}-{}-chirho",
        std::process::id(),
        NEXT_CHIRHO.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

#[test]
fn port_signed_verified_row_without_applied_receipt_grants_nothing_chirho() {
    let root_chirho = temp_root_chirho();
    let port_chirho = FakeRoutePortChirho {
        verified_chirho: RefCell::new(Vec::new()),
    };
    let state_chirho = AppRouteAuthorityStateChirho {
        schema_chirho: APP_ROUTE_AUTHORITY_STATE_SCHEMA_CHIRHO.to_string(),
        app_chirho: "example".to_string(),
        route_chirho: "status".to_string(),
        owner_principal_chirho: "owner/example".to_string(),
        dag_chirho: HashChirho("a".repeat(64)),
        action_chirho: AppRouteActionChirho::DeployRouteChirho,
        request_body_policy_chirho: None,
    };
    let (record_chirho, state_hash_chirho, _) =
        append_pending_app_route_for_test_chirho(&port_chirho, &root_chirho, &state_chirho, None)
            .unwrap();
    assert_eq!(record_chirho.sig_chirho, "root-port-signature-chirho");
    port_chirho.verified_chirho.borrow_mut().push(record_chirho);
    refs_chirho::set_branch_chirho(
        &root_chirho,
        "app-route/example/status",
        state_hash_chirho.clone(),
    )
    .unwrap();

    let error_chirho = verified_selected_app_route_record_chirho(
        &port_chirho,
        &root_chirho,
        "example",
        "status",
        "owner/example",
        &state_hash_chirho,
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("no valid Applied receipt"));
    assert!(refs_chirho::reflog_chirho(&root_chirho)
        .unwrap()
        .iter()
        .all(|entry_chirho| entry_chirho.transition_id_chirho.is_empty()));
    let _ = std::fs::remove_dir_all(root_chirho);
}
