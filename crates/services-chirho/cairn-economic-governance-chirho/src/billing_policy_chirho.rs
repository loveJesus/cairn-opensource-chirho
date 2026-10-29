// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure billing policy proposal and payer-selection helpers.

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_economic_chirho::billing_contract_chirho::{
    validate_app_name_chirho, validate_policy_chirho,
};
use cairn_model_economic_chirho::{
    AppBillingPolicyChirho, BillingOverageChirho, BillingPayerKindChirho, BillingPolicyModeChirho,
    BillingSpendCapsChirho, ResolvedBillingChirho,
};
use std::collections::BTreeMap;

pub fn propose_billing_policy_chirho(
    app_chirho: &str,
    owner_principal_chirho: &str,
    default_chirho: BillingPolicyModeChirho,
    effect_overrides_chirho: BTreeMap<String, BillingPolicyModeChirho>,
    spend_caps_chirho: BillingSpendCapsChirho,
    previous_chirho: Option<HashChirho>,
    at_ms_chirho: u64,
) -> Result<AppBillingPolicyChirho> {
    let policy_chirho = AppBillingPolicyChirho {
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: owner_principal_chirho.to_string(),
        default_chirho,
        effect_overrides_chirho,
        spend_caps_chirho,
        previous_chirho,
        at_ms_chirho,
    };
    validate_policy_chirho(&policy_chirho)?;
    Ok(policy_chirho)
}

pub fn validate_billing_resolution_input_chirho(
    app_chirho: &str,
    caller_chirho: &str,
    effect_chirho: &str,
    price_chirho: i64,
) -> Result<()> {
    validate_app_name_chirho(app_chirho)?;
    if caller_chirho.trim().is_empty() {
        bail!("caller_chirho is required");
    }
    if effect_chirho.trim().is_empty() {
        bail!("effect_chirho is required");
    }
    if price_chirho <= 0 {
        bail!("price_chirho must be positive");
    }
    Ok(())
}

pub fn select_billing_policy_mode_chirho(
    policy_chirho: &AppBillingPolicyChirho,
    effect_chirho: &str,
) -> BillingPolicyModeChirho {
    policy_chirho
        .effect_overrides_chirho
        .get(effect_chirho)
        .cloned()
        .unwrap_or_else(|| policy_chirho.default_chirho.clone())
}

#[derive(Clone, Debug)]
pub struct BillingPolicyResolutionInputChirho<'a_chirho> {
    pub app_chirho: &'a_chirho str,
    pub caller_chirho: &'a_chirho str,
    pub effect_chirho: &'a_chirho str,
    pub price_chirho: i64,
    pub owner_principal_chirho: &'a_chirho str,
    pub billing_policy_chirho: Option<HashChirho>,
    pub mode_chirho: BillingPolicyModeChirho,
    pub subsidy_used_chirho: Option<i64>,
}

pub fn resolve_billing_policy_chirho(
    input_chirho: BillingPolicyResolutionInputChirho<'_>,
) -> Result<ResolvedBillingChirho> {
    validate_billing_resolution_input_chirho(
        input_chirho.app_chirho,
        input_chirho.caller_chirho,
        input_chirho.effect_chirho,
        input_chirho.price_chirho,
    )?;
    let (payer_chirho, payer_kind_chirho) = match &input_chirho.mode_chirho {
        BillingPolicyModeChirho::UserPaysChirho => (
            input_chirho.caller_chirho.to_string(),
            BillingPayerKindChirho::UserChirho,
        ),
        BillingPolicyModeChirho::AppPaysChirho => (
            input_chirho.owner_principal_chirho.to_string(),
            BillingPayerKindChirho::AppOwnerChirho,
        ),
        BillingPolicyModeChirho::SubsidyChirho {
            per_user_budget_chirho,
            overage_chirho,
        } => {
            let _policy_hash_chirho = input_chirho
                .billing_policy_chirho
                .as_ref()
                .ok_or_else(|| anyhow!("subsidy billing requires an explicit billing policy"))?;
            let used_chirho = input_chirho
                .subsidy_used_chirho
                .ok_or_else(|| anyhow!("subsidy billing requires computed subsidy usage"))?;
            let next_chirho = used_chirho
                .checked_add(input_chirho.price_chirho)
                .ok_or_else(|| anyhow!("subsidy usage overflow"))?;
            if next_chirho <= *per_user_budget_chirho {
                (
                    input_chirho.owner_principal_chirho.to_string(),
                    BillingPayerKindChirho::SubsidyOwnerChirho,
                )
            } else {
                match overage_chirho {
                    BillingOverageChirho::FailClosedChirho => bail!(
                        "subsidy exhausted for '{}' on app '{}': used {used_chirho}, price {}, budget {per_user_budget_chirho}",
                        input_chirho.caller_chirho,
                        input_chirho.app_chirho,
                        input_chirho.price_chirho
                    ),
                    BillingOverageChirho::FallThroughUserPaysChirho => {
                        (
                            input_chirho.caller_chirho.to_string(),
                            BillingPayerKindChirho::UserChirho,
                        )
                    }
                }
            }
        }
    };
    Ok(ResolvedBillingChirho {
        app_chirho: input_chirho.app_chirho.to_string(),
        effect_chirho: input_chirho.effect_chirho.to_string(),
        caller_chirho: input_chirho.caller_chirho.to_string(),
        owner_principal_chirho: input_chirho.owner_principal_chirho.to_string(),
        payer_chirho,
        payer_kind_chirho,
        price_chirho: input_chirho.price_chirho,
        billing_policy_chirho: input_chirho.billing_policy_chirho,
        mode_chirho: input_chirho.mode_chirho,
    })
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn proposed_billing_policy_serialization_stays_stable_chirho() {
        let mut overrides_chirho = BTreeMap::new();
        overrides_chirho.insert(
            "llm_chirho".to_string(),
            BillingPolicyModeChirho::SubsidyChirho {
                per_user_budget_chirho: 31,
                overage_chirho: BillingOverageChirho::FallThroughUserPaysChirho,
            },
        );
        let policy_chirho = propose_billing_policy_chirho(
            "billingapp",
            "owner/test",
            BillingPolicyModeChirho::AppPaysChirho,
            overrides_chirho,
            BillingSpendCapsChirho {
                per_user_cap_chirho: Some(100),
                app_cap_chirho: Some(300),
            },
            Some(HashChirho("a".repeat(64))),
            1234,
        )
        .unwrap();

        assert_eq!(
            serde_json::to_string(&policy_chirho).unwrap(),
            concat!(
                r#"{"app_chirho":"billingapp","owner_principal_chirho":"owner/test","#,
                r#""default_chirho":"AppPaysChirho","effect_overrides_chirho":{"llm_chirho":{"SubsidyChirho":{"per_user_budget_chirho":31,"overage_chirho":"FallThroughUserPaysChirho"}}},"#,
                r#""spend_caps_chirho":{"per_user_cap_chirho":100,"app_cap_chirho":300},"#,
                r#""previous_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","at_ms_chirho":1234}"#
            )
        );
    }

    #[test]
    fn subsidy_without_computed_usage_fails_closed_chirho() {
        let error_chirho = resolve_billing_policy_chirho(BillingPolicyResolutionInputChirho {
            app_chirho: "billingapp",
            caller_chirho: "alice",
            effect_chirho: "llm_chirho",
            price_chirho: 17,
            owner_principal_chirho: "owner/test",
            billing_policy_chirho: Some(HashChirho("b".repeat(64))),
            mode_chirho: BillingPolicyModeChirho::SubsidyChirho {
                per_user_budget_chirho: 20,
                overage_chirho: BillingOverageChirho::FailClosedChirho,
            },
            subsidy_used_chirho: None,
        })
        .unwrap_err()
        .to_string();

        assert!(error_chirho.contains("computed subsidy usage"));
    }

    #[test]
    fn subsidy_overflow_and_exhaustion_errors_stay_stable_chirho() {
        let overflow_chirho = resolve_billing_policy_chirho(BillingPolicyResolutionInputChirho {
            app_chirho: "billingapp",
            caller_chirho: "alice",
            effect_chirho: "llm_chirho",
            price_chirho: 1,
            owner_principal_chirho: "owner/test",
            billing_policy_chirho: Some(HashChirho("c".repeat(64))),
            mode_chirho: BillingPolicyModeChirho::SubsidyChirho {
                per_user_budget_chirho: i64::MAX,
                overage_chirho: BillingOverageChirho::FailClosedChirho,
            },
            subsidy_used_chirho: Some(i64::MAX),
        })
        .unwrap_err()
        .to_string();
        assert_eq!(overflow_chirho, "subsidy usage overflow");

        let exhausted_chirho = resolve_billing_policy_chirho(BillingPolicyResolutionInputChirho {
            app_chirho: "billingapp",
            caller_chirho: "alice",
            effect_chirho: "llm_chirho",
            price_chirho: 17,
            owner_principal_chirho: "owner/test",
            billing_policy_chirho: Some(HashChirho("d".repeat(64))),
            mode_chirho: BillingPolicyModeChirho::SubsidyChirho {
                per_user_budget_chirho: 20,
                overage_chirho: BillingOverageChirho::FailClosedChirho,
            },
            subsidy_used_chirho: Some(10),
        })
        .unwrap_err()
        .to_string();
        assert_eq!(
            exhausted_chirho,
            "subsidy exhausted for 'alice' on app 'billingapp': used 10, price 17, budget 20"
        );
    }

    #[test]
    fn billing_policy_resolution_preserves_payer_modes_chirho() {
        let app_owner_chirho = resolve_billing_policy_chirho(BillingPolicyResolutionInputChirho {
            app_chirho: "billingapp",
            caller_chirho: "alice",
            effect_chirho: "llm_chirho",
            price_chirho: 17,
            owner_principal_chirho: "owner/test",
            billing_policy_chirho: Some(HashChirho("e".repeat(64))),
            mode_chirho: BillingPolicyModeChirho::AppPaysChirho,
            subsidy_used_chirho: None,
        })
        .unwrap();
        assert_eq!(app_owner_chirho.payer_chirho, "owner/test");
        assert_eq!(
            app_owner_chirho.payer_kind_chirho,
            BillingPayerKindChirho::AppOwnerChirho
        );

        let subsidy_owner_chirho =
            resolve_billing_policy_chirho(BillingPolicyResolutionInputChirho {
                app_chirho: "billingapp",
                caller_chirho: "alice",
                effect_chirho: "llm_chirho",
                price_chirho: 17,
                owner_principal_chirho: "owner/test",
                billing_policy_chirho: Some(HashChirho("f".repeat(64))),
                mode_chirho: BillingPolicyModeChirho::SubsidyChirho {
                    per_user_budget_chirho: 20,
                    overage_chirho: BillingOverageChirho::FailClosedChirho,
                },
                subsidy_used_chirho: Some(2),
            })
            .unwrap();
        assert_eq!(subsidy_owner_chirho.payer_chirho, "owner/test");
        assert_eq!(
            subsidy_owner_chirho.payer_kind_chirho,
            BillingPayerKindChirho::SubsidyOwnerChirho
        );

        let fallthrough_chirho =
            resolve_billing_policy_chirho(BillingPolicyResolutionInputChirho {
                app_chirho: "billingapp",
                caller_chirho: "alice",
                effect_chirho: "llm_chirho",
                price_chirho: 17,
                owner_principal_chirho: "owner/test",
                billing_policy_chirho: Some(HashChirho("0".repeat(64))),
                mode_chirho: BillingPolicyModeChirho::SubsidyChirho {
                    per_user_budget_chirho: 20,
                    overage_chirho: BillingOverageChirho::FallThroughUserPaysChirho,
                },
                subsidy_used_chirho: Some(10),
            })
            .unwrap();
        assert_eq!(fallthrough_chirho.payer_chirho, "alice");
        assert_eq!(
            fallthrough_chirho.payer_kind_chirho,
            BillingPayerKindChirho::UserChirho
        );
    }
}
