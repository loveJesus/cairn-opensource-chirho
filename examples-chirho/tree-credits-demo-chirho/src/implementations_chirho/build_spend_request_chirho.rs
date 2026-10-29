// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Shape the bounded spend form into Descriptor-D's fixed-coordinate reversible request. The app
//! supplies no amount, price, payer, provider mode, SQL, or compensation authority.
//!
//! Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.

use crate::types_chirho::form_post_v1_chirho::FormPostV1Chirho;
use crate::types_chirho::reversible_postgres_request_v1_chirho::{
    DesiredPostgresStateV1Chirho, ExpectedPostgresStateV1Chirho, ReversiblePostgresRequestV1Chirho,
    FIXED_ROW_KEY_CHIRHO, FIXED_SPEND_ITEM_CHIRHO, FIXED_SUBJECT_CHIRHO,
    REVERSIBLE_POSTGRES_REQUEST_SCHEMA_CHIRHO,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendRequestRefusalChirho {
    UnknownItemChirho,
    InvalidConcurrencyTokenChirho,
}

pub fn build_spend_request_chirho(
    form_chirho: &FormPostV1Chirho,
) -> Result<ReversiblePostgresRequestV1Chirho, SpendRequestRefusalChirho> {
    if form_chirho.item_chirho != FIXED_SPEND_ITEM_CHIRHO {
        return Err(SpendRequestRefusalChirho::UnknownItemChirho);
    }
    if !is_canonical_concurrency_token_chirho(&form_chirho.concurrency_token_chirho) {
        return Err(SpendRequestRefusalChirho::InvalidConcurrencyTokenChirho);
    }
    Ok(ReversiblePostgresRequestV1Chirho {
        schema_chirho: REVERSIBLE_POSTGRES_REQUEST_SCHEMA_CHIRHO.to_string(),
        subject_chirho: FIXED_SUBJECT_CHIRHO.to_string(),
        row_key_chirho: FIXED_ROW_KEY_CHIRHO.to_string(),
        expected_before_chirho: ExpectedPostgresStateV1Chirho::KeyedFingerprintChirho {
            fingerprint_chirho: form_chirho.concurrency_token_chirho.clone(),
        },
        desired_chirho: DesiredPostgresStateV1Chirho::AbsentChirho,
    })
}

fn is_canonical_concurrency_token_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && !value_chirho.bytes().all(|byte_chirho| byte_chirho == b'0')
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    const TOKEN_CHIRHO: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[test]
    fn valid_form_builds_the_exact_fixed_delete_request_chirho() {
        let request_chirho = build_spend_request_chirho(&FormPostV1Chirho {
            item_chirho: FIXED_SPEND_ITEM_CHIRHO.to_string(),
            concurrency_token_chirho: TOKEN_CHIRHO.to_string(),
        })
        .unwrap();
        assert_eq!(request_chirho.subject_chirho, FIXED_SUBJECT_CHIRHO);
        assert_eq!(request_chirho.row_key_chirho, FIXED_ROW_KEY_CHIRHO);
        assert_eq!(
            request_chirho.canonical_bytes_chirho(),
            format!(
                concat!(
                    r#"{{"schema_chirho":"reversible-postgres-request-v1-chirho","subject_chirho":"{}","row_key_chirho":"{}","expected_before_chirho":{{"kind_chirho":"keyed-fingerprint-chirho","fingerprint_chirho":"{}"}},"desired_chirho":{{"kind_chirho":"absent-chirho"}}}}"#
                ),
                FIXED_SUBJECT_CHIRHO, FIXED_ROW_KEY_CHIRHO, TOKEN_CHIRHO
            )
            .into_bytes()
        );
    }

    #[test]
    fn item_and_token_refuse_before_an_effect_request_exists_chirho() {
        for (form_chirho, expected_chirho) in [
            (
                FormPostV1Chirho {
                    item_chirho: "report-run-chirho".to_string(),
                    concurrency_token_chirho: TOKEN_CHIRHO.to_string(),
                },
                SpendRequestRefusalChirho::UnknownItemChirho,
            ),
            (
                FormPostV1Chirho {
                    item_chirho: FIXED_SPEND_ITEM_CHIRHO.to_string(),
                    concurrency_token_chirho: "C".repeat(64),
                },
                SpendRequestRefusalChirho::InvalidConcurrencyTokenChirho,
            ),
            (
                FormPostV1Chirho {
                    item_chirho: FIXED_SPEND_ITEM_CHIRHO.to_string(),
                    concurrency_token_chirho: "0".repeat(64),
                },
                SpendRequestRefusalChirho::InvalidConcurrencyTokenChirho,
            ),
        ] {
            assert_eq!(
                build_spend_request_chirho(&form_chirho),
                Err(expected_chirho)
            );
        }
    }

    #[test]
    fn serialized_request_has_no_caller_money_authority_chirho() {
        let request_chirho = build_spend_request_chirho(&FormPostV1Chirho {
            item_chirho: FIXED_SPEND_ITEM_CHIRHO.to_string(),
            concurrency_token_chirho: TOKEN_CHIRHO.to_string(),
        })
        .unwrap();
        let text_chirho = String::from_utf8(request_chirho.canonical_bytes_chirho()).unwrap();
        for forbidden_chirho in [
            "amount",
            "price",
            "payer",
            "provider",
            "sql",
            "compensation",
        ] {
            assert!(!text_chirho.contains(forbidden_chirho));
        }
    }

    #[test]
    fn injected_context_and_caller_amount_do_not_enter_the_spend_request_chirho() {
        let form_chirho = serde_json::from_value::<FormPostV1Chirho>(serde_json::json!({
            "item_chirho": FIXED_SPEND_ITEM_CHIRHO,
            "concurrency_token_chirho": TOKEN_CHIRHO,
            "amount_chirho": 999,
            "user_principal_chirho": "user/attacker"
        }))
        .unwrap();
        assert_eq!(
            form_chirho,
            FormPostV1Chirho {
                item_chirho: FIXED_SPEND_ITEM_CHIRHO.to_string(),
                concurrency_token_chirho: TOKEN_CHIRHO.to_string(),
            }
        );

        let request_chirho = build_spend_request_chirho(&form_chirho).unwrap();
        let request_text_chirho =
            String::from_utf8(request_chirho.canonical_bytes_chirho()).unwrap();
        assert!(!request_text_chirho.contains("amount"));
        assert!(!request_text_chirho.contains("principal"));
        assert!(!request_text_chirho.contains("attacker"));
    }
}
