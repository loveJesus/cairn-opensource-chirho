// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure reviewed subscription-view declarations for app source manifests.

use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubscriptionViewAuthorizationChirho {
    OwnerOnlyChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubscriptionViewDependencyGroupChirho {
    LedgerChirho,
    HoldsChirho,
    ResourcesChirho,
    BillingChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum SubscriptionViewScopeChirho {
    AppRootChirho,
    RouteChirho { route_chirho: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionViewDependencyChirho {
    pub module_input_chirho: String,
    pub group_chirho: SubscriptionViewDependencyGroupChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionViewDeclarationChirho {
    pub view_chirho: String,
    pub scope_chirho: SubscriptionViewScopeChirho,
    pub authorization_chirho: SubscriptionViewAuthorizationChirho,
    pub dependencies_chirho: Vec<SubscriptionViewDependencyChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionViewDeclarationReportChirho {
    pub declaration_chirho: HashChirho,
    pub view_chirho: String,
    pub scope_chirho: SubscriptionViewScopeChirho,
    pub authorization_chirho: SubscriptionViewAuthorizationChirho,
    pub dependencies_chirho: Vec<SubscriptionViewDependencyChirho>,
}

impl SubscriptionViewDeclarationReportChirho {
    pub fn reviewed_declaration_chirho(&self) -> SubscriptionViewDeclarationChirho {
        SubscriptionViewDeclarationChirho {
            view_chirho: self.view_chirho.clone(),
            scope_chirho: self.scope_chirho.clone(),
            authorization_chirho: self.authorization_chirho.clone(),
            dependencies_chirho: self.dependencies_chirho.clone(),
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn declaration_uses_bounded_owner_and_group_enums_chirho() {
        let declaration_chirho = SubscriptionViewDeclarationChirho {
            view_chirho: "owner-ledger-view-chirho".to_string(),
            scope_chirho: SubscriptionViewScopeChirho::RouteChirho {
                route_chirho: "ledger-chirho".to_string(),
            },
            authorization_chirho: SubscriptionViewAuthorizationChirho::OwnerOnlyChirho,
            dependencies_chirho: vec![SubscriptionViewDependencyChirho {
                module_input_chirho: "ledger-chirho".to_string(),
                group_chirho: SubscriptionViewDependencyGroupChirho::LedgerChirho,
            }],
        };
        let value_chirho = serde_json::to_value(&declaration_chirho).unwrap();
        assert_eq!(value_chirho["authorization_chirho"], "owner-only-chirho");
        assert_eq!(
            value_chirho["dependencies_chirho"][0]["group_chirho"],
            "ledger-chirho"
        );
        assert_eq!(value_chirho["scope_chirho"]["kind_chirho"], "route-chirho");
        assert!(
            serde_json::from_str::<SubscriptionViewDependencyGroupChirho>("\"coupons-chirho\"")
                .is_err()
        );
    }
}
