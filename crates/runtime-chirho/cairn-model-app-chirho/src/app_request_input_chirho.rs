// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Pure request-input policy and assembly. Callers supply already-verified identity and params;
//! these helpers do not authenticate a caller, read a root, or persist private input.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/pure-app-read-chirho.md`.

use crate::AppInputModeChirho;
use anyhow::Result;

pub const REQUEST_USER_PRIVATE_INPUT_SUBJECT_CHIRHO: &str = "request-user-chirho";

/// Classifies a verified policy only; the runtime still requires an admitted signed-in context.
pub fn allows_transient_request_user_input_chirho(mode_chirho: &AppInputModeChirho) -> bool {
    matches!(mode_chirho,
        AppInputModeChirho::PrivateBlobRefChirho { subject_chirho, safe_metadata_chirho }
        if subject_chirho == REQUEST_USER_PRIVATE_INPUT_SUBJECT_CHIRHO
            && safe_metadata_chirho.is_empty())
}

pub fn request_input_is_form_urlencoded_chirho(content_type_chirho: Option<&str>) -> bool {
    content_type_chirho
        .map(str::to_ascii_lowercase)
        .is_some_and(|value_chirho| value_chirho.starts_with("application/x-www-form-urlencoded"))
}

pub fn app_plain_input_with_verified_context_chirho(
    input_chirho: Vec<u8>,
    user_principal_chirho: Option<&str>,
    app_params_chirho: Option<&serde_json::Value>,
) -> Result<Vec<u8>> {
    if input_chirho.is_empty() {
        let mut object_chirho = serde_json::Map::new();
        if let Some(principal_chirho) = user_principal_chirho {
            object_chirho.insert(
                "user_principal_chirho".to_string(),
                serde_json::Value::String(principal_chirho.to_string()),
            );
        }
        if let Some(app_params_chirho) = app_params_chirho {
            object_chirho.insert("app_params_chirho".to_string(), app_params_chirho.clone());
        }
        if object_chirho.is_empty() {
            return Ok(input_chirho);
        }
        return Ok(serde_json::to_vec(&serde_json::Value::Object(
            object_chirho,
        ))?);
    }
    let Ok(mut value_chirho) = serde_json::from_slice::<serde_json::Value>(&input_chirho) else {
        return Ok(input_chirho);
    };
    let Some(object_chirho) = value_chirho.as_object_mut() else {
        return Ok(input_chirho);
    };
    let mut changed_chirho = object_chirho.remove("user_principal_chirho").is_some();
    changed_chirho |= object_chirho.remove("app_params_chirho").is_some();
    if let Some(principal_chirho) = user_principal_chirho {
        object_chirho.insert(
            "user_principal_chirho".to_string(),
            serde_json::Value::String(principal_chirho.to_string()),
        );
        changed_chirho = true;
    }
    if let Some(app_params_chirho) = app_params_chirho {
        object_chirho.insert("app_params_chirho".to_string(), app_params_chirho.clone());
        changed_chirho = true;
    }
    if !changed_chirho {
        return Ok(input_chirho);
    }
    Ok(serde_json::to_vec(&value_chirho)?)
}

#[cfg(test)]
#[path = "tests_chirho/request_input_tests_chirho.rs"]
mod tests_chirho;
