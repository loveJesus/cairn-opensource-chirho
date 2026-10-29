// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::model_chirho::{CapabilityChirho, DagChirho, NodeDefChirho, RequestContextChirho};
use crate::resource_chirho::{
    ResourceActionPolicyChirho, ResourceChargeChirho, ResourceMeterChirho, ResourceOverageChirho,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const TEMPLATE_ID_CHIRHO: &str = "tree-template-landing-chirho";
const BUILDER_APP_CHIRHO: &str = "perffection-builder-chirho";

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-template-app-deploy-test-{nanos_chirho}-{n_chirho}"
    ))
}

struct TemplateDeployFixtureChirho {
    root_chirho: PathBuf,
    user_chirho: String,
    builder_owner_chirho: String,
}

impl TemplateDeployFixtureChirho {
    fn new_chirho(limit_chirho: i64) -> Self {
        Self::new_with_effectful_template_chirho(limit_chirho, false)
    }

    fn new_with_effectful_template_chirho(
        limit_chirho: i64,
        effectful_template_chirho: bool,
    ) -> Self {
        let root_chirho = tmp_root_chirho();
        let builder_owner_chirho = principal_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
        );
        let user_chirho = principal_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::UserChirho,
        );
        let builder_dag_chirho = fake_dag_chirho(&root_chirho);
        let template_dag_chirho = if effectful_template_chirho {
            effectful_legacy_dag_chirho(&root_chirho)
        } else {
            fake_dag_chirho(&root_chirho)
        };
        crate::app_chirho::deploy_app_chirho(
            &root_chirho,
            BUILDER_APP_CHIRHO,
            builder_dag_chirho,
            &builder_owner_chirho,
        )
        .unwrap();
        set_template_deploy_policy_chirho(
            &root_chirho,
            &builder_owner_chirho,
            BUILDER_APP_CHIRHO,
            limit_chirho,
        );
        crate::app_chirho::register_template_app_template_chirho(
            &root_chirho,
            crate::app_chirho::TemplateRegistryInputChirho {
                template_id_chirho: TEMPLATE_ID_CHIRHO.to_string(),
                root_dag_chirho: template_dag_chirho.clone(),
                response_content_type_chirho: "text/html".to_string(),
            },
        )
        .unwrap();
        Self {
            root_chirho,
            user_chirho,
            builder_owner_chirho,
        }
    }

    fn context_chirho(&self) -> RequestContextChirho {
        RequestContextChirho {
            user_principal_chirho: self.user_chirho.clone(),
            app_chirho: BUILDER_APP_CHIRHO.to_string(),
            owner_principal_chirho: self.builder_owner_chirho.clone(),
            client_id_chirho: "client/app-builder-test-chirho".to_string(),
            token_hash_chirho: "token/app-builder-test-chirho".to_string(),
            price_book_chirho: None,
            billing_policy_chirho: None,
            key_limit_chirho: None,
        }
    }
}

fn principal_chirho(
    root_chirho: &Path,
    kind_chirho: identity_chirho::PrincipalKindChirho,
) -> String {
    identity_chirho::register_identity_chirho(root_chirho, kind_chirho)
        .unwrap()
        .principal_chirho
}

fn fake_dag_chirho(root_chirho: &Path) -> HashChirho {
    let dag_chirho = DagChirho {
        nodes_chirho: Vec::new(),
        edges_chirho: Vec::new(),
    };
    crate::store_chirho::put_object_chirho(root_chirho, &dag_chirho).unwrap()
}

fn effectful_legacy_dag_chirho(root_chirho: &Path) -> HashChirho {
    let node_chirho = NodeDefChirho {
        name_chirho: "legacy-template-write-chirho".to_string(),
        capabilities_chirho: vec![CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "apps/legacy-template-chirho".to_string(),
        }],
        ..Default::default()
    };
    let node_chirho = crate::store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    crate::store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap()
}

fn set_template_deploy_policy_chirho(
    root_chirho: &Path,
    owner_chirho: &str,
    app_chirho: &str,
    limit_chirho: i64,
) {
    crate::resource_chirho::set_resource_policy_chirho(
        root_chirho,
        app_chirho,
        owner_chirho,
        vec![ResourceMeterChirho {
            resource_chirho: "template-apps-chirho".to_string(),
            unit_chirho: "build-chirho".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: Some(limit_chirho),
            app_limit_chirho: None,
            window_ms_chirho: None,
            overage_chirho: ResourceOverageChirho::FailClosedChirho,
        }],
        vec![ResourceActionPolicyChirho {
            section_chirho: TEMPLATE_APP_DEPLOY_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: TEMPLATE_APP_DEPLOY_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: Some(TEMPLATE_APP_DEPLOY_EFFECT_CHIRHO.to_string()),
            allow_anonymous_chirho: false,
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: "template-apps-chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap();
}

fn request_chirho(slug_chirho: &str, idem_chirho: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_chirho": TEMPLATE_APP_DEPLOY_REQUEST_SCHEMA_CHIRHO,
        "slug_chirho": slug_chirho,
        "idem_key_chirho": idem_chirho,
        "owner_principal_chirho": "owner/spoof-chirho",
        "params_chirho": {
            "business_name_chirho": "Cornerstone Bistro",
            "tagline_chirho": "Seasonal neighborhood dinners"
        }
    }))
    .unwrap()
}

fn run_deploy_chirho(
    fixture_chirho: &TemplateDeployFixtureChirho,
    slug_chirho: &str,
    idem_chirho: &str,
) -> TemplateAppDeployResponseChirho {
    let bytes_chirho = run_template_app_deploy_effect_chirho(
        &fixture_chirho.root_chirho,
        TEMPLATE_ID_CHIRHO,
        &request_chirho(slug_chirho, idem_chirho),
        Some(&fixture_chirho.context_chirho()),
    )
    .unwrap();
    serde_json::from_slice(&bytes_chirho).unwrap()
}

#[test]
fn effectful_legacy_template_refuses_before_quota_owner_or_app_mutation_chirho() {
    let fixture_chirho = TemplateDeployFixtureChirho::new_with_effectful_template_chirho(3, true);
    let error_chirho = run_template_app_deploy_effect_chirho(
        &fixture_chirho.root_chirho,
        TEMPLATE_ID_CHIRHO,
        &request_chirho("blocked-template-chirho", "idem-blocked"),
        Some(&fixture_chirho.context_chirho()),
    )
    .unwrap_err();

    assert!(error_chirho
        .to_string()
        .contains("requires complete verified undo-plan bindings"));
    assert!(
        crate::resource_chirho::load_resource_usage_chirho(&fixture_chirho.root_chirho)
            .unwrap()
            .is_empty()
    );
    assert!(crate::app_chirho::load_client_owner_binding_records_chirho(
        &fixture_chirho.root_chirho
    )
    .unwrap()
    .is_empty());
    assert!(
        load_template_app_deploy_records_chirho(&fixture_chirho.root_chirho)
            .unwrap()
            .is_empty()
    );

    let _ = std::fs::remove_dir_all(&fixture_chirho.root_chirho);
}

#[test]
fn template_app_deploy_mints_owner_deploys_params_and_ignores_caller_owner_chirho() {
    let fixture_chirho = TemplateDeployFixtureChirho::new_chirho(3);

    let response_chirho = run_deploy_chirho(&fixture_chirho, "cornerstone-bistro-chirho", "idem-a");

    assert_eq!(
        response_chirho.user_principal_chirho,
        fixture_chirho.user_chirho
    );
    assert_ne!(response_chirho.owner_principal_chirho, "owner/spoof-chirho");
    assert_ne!(
        response_chirho.owner_principal_chirho,
        fixture_chirho.builder_owner_chirho
    );
    assert_eq!(response_chirho.template_id_chirho, TEMPLATE_ID_CHIRHO);
    assert_eq!(
        crate::app_chirho::verified_app_owner_chirho(
            &fixture_chirho.root_chirho,
            &response_chirho.app_chirho,
        )
        .unwrap(),
        Some(response_chirho.owner_principal_chirho.clone())
    );
    let params_chirho = crate::app_chirho::app_params_chirho(
        &fixture_chirho.root_chirho,
        &response_chirho.app_chirho,
        None,
        &response_chirho.owner_principal_chirho,
    )
    .unwrap()
    .unwrap();
    assert!(params_chirho.required_chirho);
    assert_eq!(params_chirho.params_chirho, response_chirho.params_chirho);
    assert_eq!(
        params_chirho.value_chirho["business_name_chirho"],
        "Cornerstone Bistro"
    );
    assert!(matches!(
        crate::app_chirho::app_input_mode_chirho(
            &fixture_chirho.root_chirho,
            &response_chirho.app_chirho,
            None,
            &response_chirho.owner_principal_chirho,
        )
        .unwrap(),
        crate::app_chirho::AppInputModeChirho::PlainChirho
    ));
    assert_eq!(
        crate::app_chirho::verify_app_input_policies_chirho(&fixture_chirho.root_chirho).unwrap(),
        1
    );
    assert_eq!(
        crate::app_chirho::load_client_owner_binding_records_chirho(&fixture_chirho.root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        crate::app_chirho::verify_template_app_deploy_records_chirho(&fixture_chirho.root_chirho)
            .unwrap(),
        1
    );
    assert_eq!(
        crate::resource_chirho::load_resource_usage_chirho(&fixture_chirho.root_chirho)
            .unwrap()
            .len(),
        1
    );

    let _ = std::fs::remove_dir_all(&fixture_chirho.root_chirho);
}

#[test]
fn template_app_deploy_reuses_owner_and_idempotency_key_chirho() {
    let fixture_chirho = TemplateDeployFixtureChirho::new_chirho(5);

    let first_chirho = run_deploy_chirho(&fixture_chirho, "first-shop-chirho", "idem-replay");
    let replay_chirho = run_deploy_chirho(&fixture_chirho, "first-shop-chirho", "idem-replay");
    let second_chirho = run_deploy_chirho(&fixture_chirho, "second-shop-chirho", "idem-second");

    assert_eq!(first_chirho, replay_chirho);
    assert_eq!(
        first_chirho.owner_principal_chirho,
        second_chirho.owner_principal_chirho
    );
    assert_ne!(first_chirho.app_chirho, second_chirho.app_chirho);
    assert_eq!(
        crate::app_chirho::load_client_owner_binding_records_chirho(&fixture_chirho.root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        crate::app_chirho::load_template_app_deploy_records_chirho(&fixture_chirho.root_chirho)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        crate::resource_chirho::load_resource_usage_chirho(&fixture_chirho.root_chirho)
            .unwrap()
            .len(),
        2
    );

    let conflict_error_chirho = run_template_app_deploy_effect_chirho(
        &fixture_chirho.root_chirho,
        TEMPLATE_ID_CHIRHO,
        &request_chirho("changed-shop-chirho", "idem-replay"),
        Some(&fixture_chirho.context_chirho()),
    )
    .unwrap_err()
    .to_string();
    assert!(conflict_error_chirho.contains("idempotency key conflict"));

    let _ = std::fs::remove_dir_all(&fixture_chirho.root_chirho);
}

#[test]
fn template_app_deploy_fails_closed_without_session_unknown_template_or_bad_slug_chirho() {
    let fixture_chirho = TemplateDeployFixtureChirho::new_chirho(3);

    let no_session_error_chirho = run_template_app_deploy_effect_chirho(
        &fixture_chirho.root_chirho,
        TEMPLATE_ID_CHIRHO,
        &request_chirho("sessionless-chirho", "idem-no-session"),
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(no_session_error_chirho.contains("requires a signed-in app session"));

    let unknown_template_error_chirho = run_template_app_deploy_effect_chirho(
        &fixture_chirho.root_chirho,
        "unknown-template-chirho",
        &request_chirho("unknown-template-chirho", "idem-unknown"),
        Some(&fixture_chirho.context_chirho()),
    )
    .unwrap_err()
    .to_string();
    assert!(unknown_template_error_chirho.contains("not allowlisted"));

    let bad_slug_error_chirho = run_template_app_deploy_effect_chirho(
        &fixture_chirho.root_chirho,
        TEMPLATE_ID_CHIRHO,
        &request_chirho("../bad", "idem-bad-slug"),
        Some(&fixture_chirho.context_chirho()),
    )
    .unwrap_err()
    .to_string();
    assert!(bad_slug_error_chirho.contains("slug_chirho"));
    assert_eq!(
        crate::app_chirho::load_client_owner_binding_records_chirho(&fixture_chirho.root_chirho)
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        crate::app_chirho::load_template_app_deploy_records_chirho(&fixture_chirho.root_chirho)
            .unwrap()
            .len(),
        0
    );

    let _ = std::fs::remove_dir_all(&fixture_chirho.root_chirho);
}

#[test]
fn template_app_deploy_rejects_existing_slug_and_quota_overage_chirho() {
    let fixture_chirho = TemplateDeployFixtureChirho::new_chirho(1);

    let first_chirho = run_deploy_chirho(&fixture_chirho, "quota-shop-chirho", "idem-first");
    let overage_error_chirho = run_template_app_deploy_effect_chirho(
        &fixture_chirho.root_chirho,
        TEMPLATE_ID_CHIRHO,
        &request_chirho("another-shop-chirho", "idem-overage"),
        Some(&fixture_chirho.context_chirho()),
    )
    .unwrap_err()
    .to_string();
    assert!(overage_error_chirho.contains("exhausted"));
    assert_eq!(
        crate::app_chirho::load_template_app_deploy_records_chirho(&fixture_chirho.root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        crate::resource_chirho::load_resource_usage_chirho(&fixture_chirho.root_chirho)
            .unwrap()
            .len(),
        1
    );

    set_template_deploy_policy_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.builder_owner_chirho,
        BUILDER_APP_CHIRHO,
        5,
    );
    let existing_slug_error_chirho = run_template_app_deploy_effect_chirho(
        &fixture_chirho.root_chirho,
        TEMPLATE_ID_CHIRHO,
        &request_chirho("quota-shop-chirho", "idem-existing"),
        Some(&fixture_chirho.context_chirho()),
    )
    .unwrap_err()
    .to_string();
    assert!(existing_slug_error_chirho.contains("slug already exists"));
    assert_eq!(
        crate::app_chirho::verified_app_owner_chirho(
            &fixture_chirho.root_chirho,
            &first_chirho.app_chirho,
        )
        .unwrap(),
        Some(first_chirho.owner_principal_chirho)
    );

    let _ = std::fs::remove_dir_all(&fixture_chirho.root_chirho);
}
