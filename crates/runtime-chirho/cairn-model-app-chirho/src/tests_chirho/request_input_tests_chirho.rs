// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::AppPrivateInputSafeMetadataChirho;
use serde_json::{json, Value};

#[test]
fn transient_policy_accepts_only_request_user_without_metadata_chirho() {
    let accepted_chirho = AppInputModeChirho::PrivateBlobRefChirho {
        subject_chirho: REQUEST_USER_PRIVATE_INPUT_SUBJECT_CHIRHO.into(),
        safe_metadata_chirho: Vec::new(),
    };
    assert!(allows_transient_request_user_input_chirho(&accepted_chirho));
    for mode_chirho in [
        AppInputModeChirho::PlainChirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "declared-private-chirho".into(),
            safe_metadata_chirho: Vec::new(),
        },
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: REQUEST_USER_PRIVATE_INPUT_SUBJECT_CHIRHO.into(),
            safe_metadata_chirho: vec![AppPrivateInputSafeMetadataChirho {
                key_chirho: "request_kind_chirho".into(),
                allowed_values_chirho: vec!["review_chirho".into()],
            }],
        },
    ] {
        assert!(!allows_transient_request_user_input_chirho(&mode_chirho));
    }
}

#[test]
fn plain_input_uses_only_verified_identity_and_params_chirho() {
    let posted_chirho = json!({
        "user_principal_chirho": "forged-user-chirho",
        "app_params_chirho": {"forged_chirho": true},
        "body_chirho": "submitted content chirho"
    });
    let params_chirho = json!({"declared_chirho": "verified-chirho"});
    let input_chirho = serde_json::to_vec(&posted_chirho).unwrap();
    let actual_chirho = app_plain_input_with_verified_context_chirho(
        input_chirho.clone(),
        Some("verified-user-chirho"),
        Some(&params_chirho),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&actual_chirho).unwrap(),
        json!({
            "user_principal_chirho": "verified-user-chirho",
            "app_params_chirho": params_chirho,
            "body_chirho": "submitted content chirho"
        })
    );
    let anonymous_chirho =
        app_plain_input_with_verified_context_chirho(input_chirho, None, None).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&anonymous_chirho).unwrap(),
        json!({"body_chirho": "submitted content chirho"})
    );
}

#[test]
fn empty_input_receives_context_but_unmodified_payloads_preserve_their_bytes_chirho() {
    assert!(
        app_plain_input_with_verified_context_chirho(Vec::new(), None, None)
            .unwrap()
            .is_empty()
    );
    let params_chirho = json!({"view_chirho": "current-chirho"});
    let assembled_chirho = app_plain_input_with_verified_context_chirho(
        Vec::new(),
        Some("verified-user-chirho"),
        Some(&params_chirho),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&assembled_chirho).unwrap(),
        json!({"user_principal_chirho": "verified-user-chirho", "app_params_chirho": params_chirho})
    );
    for bytes_chirho in [
        b"opaque non-json chirho".as_slice(),
        b"[1, 2, 3]".as_slice(),
        b"\"json string chirho\"".as_slice(),
    ] {
        assert_eq!(
            app_plain_input_with_verified_context_chirho(
                bytes_chirho.to_vec(),
                Some("verified-user-chirho"),
                Some(&params_chirho),
            )
            .unwrap(),
            bytes_chirho
        );
    }
    let object_chirho = b"{ \"body_chirho\" : \"spacing preserved chirho\" }";
    assert_eq!(
        app_plain_input_with_verified_context_chirho(object_chirho.to_vec(), None, None).unwrap(),
        object_chirho
    );
}

#[test]
fn form_content_type_classification_keeps_the_existing_case_insensitive_rule_chirho() {
    assert!(request_input_is_form_urlencoded_chirho(Some(
        "Application/X-Www-Form-Urlencoded; charset=UTF-8"
    )));
    for content_type_chirho in [None, Some("application/json"), Some("multipart/form-data")] {
        assert!(!request_input_is_form_urlencoded_chirho(
            content_type_chirho
        ));
    }
}
