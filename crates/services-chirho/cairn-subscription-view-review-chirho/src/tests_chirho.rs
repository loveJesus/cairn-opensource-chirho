// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure service tests for subscription-view review policy.

use super::*;
use cairn_model_app_chirho::{
    SubscriptionViewAuthorizationChirho, SubscriptionViewDependencyChirho,
    SubscriptionViewDependencyGroupChirho,
};

fn declaration_report_chirho(
    view_chirho: &str,
    scope_chirho: SubscriptionViewScopeChirho,
) -> SubscriptionViewDeclarationReportChirho {
    SubscriptionViewDeclarationReportChirho {
        declaration_chirho: HashChirho("a".repeat(64)),
        view_chirho: view_chirho.to_string(),
        scope_chirho,
        authorization_chirho: SubscriptionViewAuthorizationChirho::OwnerOnlyChirho,
        dependencies_chirho: vec![SubscriptionViewDependencyChirho {
            module_input_chirho: "ledger_chirho".to_string(),
            group_chirho: SubscriptionViewDependencyGroupChirho::LedgerChirho,
        }],
    }
}

#[test]
fn candidate_scope_validation_binds_root_and_route_dags_chirho() {
    let dag_chirho = HashChirho("b".repeat(64));
    let module_chirho = AppSourceModuleReportChirho {
        id_chirho: "module-chirho".to_string(),
        module_chirho: HashChirho("c".repeat(64)),
        dag_chirho: dag_chirho.clone(),
        subscription_views_chirho: vec![declaration_report_chirho(
            "view-chirho",
            SubscriptionViewScopeChirho::RouteChirho {
                route_chirho: "summary-chirho".to_string(),
            },
        )],
    };
    let routes_chirho = BTreeMap::from([("summary-chirho".to_string(), dag_chirho.clone())]);
    validate_subscription_view_scopes_chirho(
        &HashChirho("d".repeat(64)),
        &routes_chirho,
        std::slice::from_ref(&module_chirho),
    )
    .unwrap();

    let error_chirho = validate_subscription_view_scopes_chirho(
        &HashChirho("d".repeat(64)),
        &BTreeMap::from([("summary-chirho".to_string(), HashChirho("e".repeat(64)))]),
        &[module_chirho],
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("does not resolve to module DAG"));
}
