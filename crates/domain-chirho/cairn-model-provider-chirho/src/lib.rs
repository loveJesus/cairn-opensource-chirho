// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure provider model and port records.
//!
//! This crate owns provider-neutral request/result shapes and tiny port traits only. It does not
//! perform HTTP, read a cairn root, sign records, mutate ledgers, store private blobs, or verify
//! provider-specific webhook signatures.

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub const OPENROUTER_PROVIDER_CHIRHO: &str = "openrouter";
pub const OPENROUTER_DEEPSEEK_V4_MODEL_CHIRHO: &str = "deepseek/deepseek-v4-flash";
pub const OPENROUTER_CHAT_COMPLETIONS_URL_CHIRHO: &str =
    "https://openrouter.ai/api/v1/chat/completions";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAccountStatusRequestChirho {
    pub provider_account_id_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderConnectedAccountStatusChirho {
    pub provider_account_id_chirho: String,
    pub payouts_enabled_chirho: bool,
    pub charges_enabled_chirho: bool,
    pub details_submitted_chirho: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requirements_currently_due_chirho: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requirements_past_due_chirho: Vec<String>,
}

pub trait ProviderAccountStatusPortChirho {
    fn fetch_connected_account_status_chirho(
        &self,
        request_chirho: ProviderAccountStatusRequestChirho,
    ) -> Result<ProviderConnectedAccountStatusChirho>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderConnectOnboardingRequestChirho {
    pub principal_chirho: String,
    pub return_url_chirho: String,
    pub refresh_url_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderConnectAccountLinkRequestChirho {
    pub provider_account_id_chirho: String,
    pub return_url_chirho: String,
    pub refresh_url_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderConnectOnboardingChirho {
    pub provider_account_id_chirho: String,
    pub onboarding_url_chirho: String,
}

pub trait ProviderConnectOnboardingPortChirho {
    fn create_connected_account_onboarding_chirho(
        &self,
        request_chirho: ProviderConnectOnboardingRequestChirho,
    ) -> Result<ProviderConnectOnboardingChirho>;

    fn create_connected_account_link_chirho(
        &self,
        request_chirho: ProviderConnectAccountLinkRequestChirho,
    ) -> Result<String>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderTransferRequestChirho {
    pub amount_cents_chirho: i64,
    pub provider_account_id_chirho: String,
    pub idempotency_key_chirho: String,
    pub principal_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderTransferCreatedChirho {
    pub provider_transfer_id_chirho: String,
}

pub trait ProviderTransferPortChirho {
    fn create_transfer_chirho(
        &self,
        request_chirho: ProviderTransferRequestChirho,
    ) -> Result<ProviderTransferCreatedChirho>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCheckoutSessionRequestChirho {
    pub account_chirho: String,
    pub amount_cents_chirho: i64,
    pub success_url_chirho: String,
    pub cancel_url_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCheckoutSessionCreatedChirho {
    pub checkout_url_chirho: String,
}

pub trait ProviderCheckoutPortChirho {
    fn create_checkout_session_chirho(
        &self,
        request_chirho: ProviderCheckoutSessionRequestChirho,
    ) -> Result<ProviderCheckoutSessionCreatedChirho>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderWebhookRequestChirho {
    pub payload_chirho: Vec<u8>,
    pub signature_header_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum ProviderWebhookEventChirho {
    CheckoutSessionCompletedChirho {
        provider_event_id_chirho: String,
        account_chirho: String,
        amount_cents_chirho: i64,
    },
    IgnoredChirho {
        provider_event_type_chirho: String,
    },
}

pub trait ProviderWebhookPortChirho {
    fn verify_and_parse_webhook_event_chirho(
        &self,
        request_chirho: ProviderWebhookRequestChirho,
    ) -> Result<ProviderWebhookEventChirho>;
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn provider_account_status_omits_empty_optional_fields_chirho() {
        let status_chirho = ProviderConnectedAccountStatusChirho {
            provider_account_id_chirho: "acct_test_chirho".to_string(),
            payouts_enabled_chirho: true,
            charges_enabled_chirho: true,
            details_submitted_chirho: true,
            disabled_reason_chirho: None,
            requirements_currently_due_chirho: Vec::new(),
            requirements_past_due_chirho: Vec::new(),
        };

        let value_chirho = serde_json::to_value(&status_chirho).unwrap();
        assert!(value_chirho.get("disabled_reason_chirho").is_none());
        assert!(value_chirho
            .get("requirements_currently_due_chirho")
            .is_none());
        assert!(value_chirho.get("requirements_past_due_chirho").is_none());
    }

    #[test]
    fn provider_account_status_trait_returns_observation_chirho() {
        struct StubProviderChirho;

        impl ProviderAccountStatusPortChirho for StubProviderChirho {
            fn fetch_connected_account_status_chirho(
                &self,
                request_chirho: ProviderAccountStatusRequestChirho,
            ) -> Result<ProviderConnectedAccountStatusChirho> {
                Ok(ProviderConnectedAccountStatusChirho {
                    provider_account_id_chirho: request_chirho.provider_account_id_chirho,
                    payouts_enabled_chirho: false,
                    charges_enabled_chirho: true,
                    details_submitted_chirho: false,
                    disabled_reason_chirho: Some("requirements.currently_due".to_string()),
                    requirements_currently_due_chirho: vec!["external_account".to_string()],
                    requirements_past_due_chirho: Vec::new(),
                })
            }
        }

        let provider_chirho = StubProviderChirho;
        let status_chirho = provider_chirho
            .fetch_connected_account_status_chirho(ProviderAccountStatusRequestChirho {
                provider_account_id_chirho: "acct_test_chirho".to_string(),
            })
            .unwrap();

        assert_eq!(status_chirho.provider_account_id_chirho, "acct_test_chirho");
        assert!(!status_chirho.payouts_enabled_chirho);
        assert_eq!(
            status_chirho.requirements_currently_due_chirho,
            vec!["external_account"]
        );
    }

    #[test]
    fn provider_connect_onboarding_result_has_no_signed_fields_chirho() {
        let onboarding_chirho = ProviderConnectOnboardingChirho {
            provider_account_id_chirho: "acct_test_chirho".to_string(),
            onboarding_url_chirho: "https://connect.stripe.com/setup/test".to_string(),
        };

        let value_chirho = serde_json::to_value(&onboarding_chirho).unwrap();
        assert!(value_chirho.get("schema_chirho").is_none());
        assert!(value_chirho.get("seq_chirho").is_none());
        assert!(value_chirho.get("sig_chirho").is_none());
    }

    #[test]
    fn provider_connect_onboarding_trait_returns_transient_url_chirho() {
        struct StubProviderChirho;

        impl ProviderConnectOnboardingPortChirho for StubProviderChirho {
            fn create_connected_account_onboarding_chirho(
                &self,
                request_chirho: ProviderConnectOnboardingRequestChirho,
            ) -> Result<ProviderConnectOnboardingChirho> {
                Ok(ProviderConnectOnboardingChirho {
                    provider_account_id_chirho: request_chirho.principal_chirho,
                    onboarding_url_chirho: request_chirho.return_url_chirho,
                })
            }

            fn create_connected_account_link_chirho(
                &self,
                request_chirho: ProviderConnectAccountLinkRequestChirho,
            ) -> Result<String> {
                Ok(request_chirho.refresh_url_chirho)
            }
        }

        let provider_chirho = StubProviderChirho;
        let onboarding_chirho = provider_chirho
            .create_connected_account_onboarding_chirho(ProviderConnectOnboardingRequestChirho {
                principal_chirho: "acct_test_chirho".to_string(),
                return_url_chirho: "https://connect.stripe.com/setup/test".to_string(),
                refresh_url_chirho: "https://connect.stripe.com/refresh/test".to_string(),
            })
            .unwrap();
        let link_chirho = provider_chirho
            .create_connected_account_link_chirho(ProviderConnectAccountLinkRequestChirho {
                provider_account_id_chirho: onboarding_chirho.provider_account_id_chirho.clone(),
                return_url_chirho: onboarding_chirho.onboarding_url_chirho.clone(),
                refresh_url_chirho: "https://connect.stripe.com/refresh/again".to_string(),
            })
            .unwrap();

        assert_eq!(
            onboarding_chirho.provider_account_id_chirho,
            "acct_test_chirho"
        );
        assert_eq!(link_chirho, "https://connect.stripe.com/refresh/again");
    }

    #[test]
    fn provider_transfer_created_has_no_signed_fields_chirho() {
        let transfer_chirho = ProviderTransferCreatedChirho {
            provider_transfer_id_chirho: "tr_test_chirho".to_string(),
        };

        let value_chirho = serde_json::to_value(&transfer_chirho).unwrap();
        assert!(value_chirho.get("schema_chirho").is_none());
        assert!(value_chirho.get("seq_chirho").is_none());
        assert!(value_chirho.get("sig_chirho").is_none());
    }

    #[test]
    fn provider_transfer_trait_returns_unsigned_observation_chirho() {
        struct StubProviderChirho;

        impl ProviderTransferPortChirho for StubProviderChirho {
            fn create_transfer_chirho(
                &self,
                request_chirho: ProviderTransferRequestChirho,
            ) -> Result<ProviderTransferCreatedChirho> {
                Ok(ProviderTransferCreatedChirho {
                    provider_transfer_id_chirho: format!(
                        "tr_{}",
                        request_chirho.idempotency_key_chirho
                    ),
                })
            }
        }

        let provider_chirho = StubProviderChirho;
        let transfer_chirho = provider_chirho
            .create_transfer_chirho(ProviderTransferRequestChirho {
                amount_cents_chirho: 10,
                provider_account_id_chirho: "acct_test_chirho".to_string(),
                idempotency_key_chirho: "idem_chirho".to_string(),
                principal_chirho: "owner/test_chirho".to_string(),
            })
            .unwrap();

        assert_eq!(
            transfer_chirho.provider_transfer_id_chirho,
            "tr_idem_chirho"
        );
    }

    #[test]
    fn provider_checkout_session_created_has_no_signed_fields_chirho() {
        let checkout_chirho = ProviderCheckoutSessionCreatedChirho {
            checkout_url_chirho: "https://checkout.stripe.com/c/test_chirho".to_string(),
        };

        let value_chirho = serde_json::to_value(&checkout_chirho).unwrap();
        assert!(value_chirho.get("schema_chirho").is_none());
        assert!(value_chirho.get("seq_chirho").is_none());
        assert!(value_chirho.get("sig_chirho").is_none());
    }

    #[test]
    fn provider_checkout_trait_returns_transient_url_chirho() {
        struct StubProviderChirho;

        impl ProviderCheckoutPortChirho for StubProviderChirho {
            fn create_checkout_session_chirho(
                &self,
                request_chirho: ProviderCheckoutSessionRequestChirho,
            ) -> Result<ProviderCheckoutSessionCreatedChirho> {
                Ok(ProviderCheckoutSessionCreatedChirho {
                    checkout_url_chirho: request_chirho.success_url_chirho,
                })
            }
        }

        let provider_chirho = StubProviderChirho;
        let checkout_chirho = provider_chirho
            .create_checkout_session_chirho(ProviderCheckoutSessionRequestChirho {
                account_chirho: "owner/test_chirho".to_string(),
                amount_cents_chirho: 10,
                success_url_chirho: "https://checkout.stripe.com/success".to_string(),
                cancel_url_chirho: "https://checkout.stripe.com/cancel".to_string(),
            })
            .unwrap();

        assert_eq!(
            checkout_chirho.checkout_url_chirho,
            "https://checkout.stripe.com/success"
        );
    }

    #[test]
    fn provider_webhook_event_has_no_signed_fields_chirho() {
        let event_chirho = ProviderWebhookEventChirho::CheckoutSessionCompletedChirho {
            provider_event_id_chirho: "evt_test_chirho".to_string(),
            account_chirho: "owner/test_chirho".to_string(),
            amount_cents_chirho: 10,
        };

        let value_chirho = serde_json::to_value(&event_chirho).unwrap();
        assert!(value_chirho.get("schema_chirho").is_none());
        assert!(value_chirho.get("seq_chirho").is_none());
        assert!(value_chirho.get("sig_chirho").is_none());
        assert_eq!(
            value_chirho["kind_chirho"],
            "checkout-session-completed-chirho"
        );
    }

    #[test]
    fn provider_webhook_trait_returns_unsigned_observation_chirho() {
        struct StubProviderChirho;

        impl ProviderWebhookPortChirho for StubProviderChirho {
            fn verify_and_parse_webhook_event_chirho(
                &self,
                request_chirho: ProviderWebhookRequestChirho,
            ) -> Result<ProviderWebhookEventChirho> {
                assert!(!request_chirho.payload_chirho.is_empty());
                Ok(ProviderWebhookEventChirho::IgnoredChirho {
                    provider_event_type_chirho: request_chirho.signature_header_chirho,
                })
            }
        }

        let provider_chirho = StubProviderChirho;
        let event_chirho = provider_chirho
            .verify_and_parse_webhook_event_chirho(ProviderWebhookRequestChirho {
                payload_chirho: b"{}".to_vec(),
                signature_header_chirho: "test.event".to_string(),
            })
            .unwrap();

        assert_eq!(
            event_chirho,
            ProviderWebhookEventChirho::IgnoredChirho {
                provider_event_type_chirho: "test.event".to_string()
            }
        );
    }
}
