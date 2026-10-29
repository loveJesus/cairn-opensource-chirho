// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Boundary entry for the validate role (bytes ABI). Wraps the untrusted model completion bytes as
//! the completion text, calls the strict pure validator (validate_build_params_chirho), and
//! serializes the DeployRequestV1Chirho the blessed template-deploy door consumes.
//!
//! The upstream blessed `llm` door emits the RAW model-completion content bytes (the literal JSON
//! object the model produced, e.g. `{"business_name_chirho":...,"features_chirho":[...]}`), NOT a
//! `{"text_chirho":...}` wrapper. So these input bytes ARE the completion text: we read them as UTF-8
//! and hand them to the validator, whose impl parses that text as the params JSON.
//!
//! Fail-closed convention: the validator returns `Err` on ANY invalid model output. In that case
//! this guest emits the SDK's non-deploy error envelope (`{"error_chirho":"json-chirho"}`) instead
//! of a deploy request. That envelope is NOT a valid `TemplateAppDeployRequestChirho`, so the blessed
//! deploy door's request decode / required-field / slug validation rejects it before any deploy - no
//! app is ever deployed from bad model output.

use tree_app_builder_chirho::implementations_chirho::validate_build_params_chirho::validate_build_params_chirho as validate_build_params_impl_fn_chirho;
use tree_app_builder_chirho::types_chirho::llm_completion_v1_chirho::LlmCompletionV1Chirho;

fn validate_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    // The blessed llm door returns the raw completion content bytes (not a wrapped object), so the
    // input bytes are the completion text the strict validator parses as the params JSON.
    let text_chirho = String::from_utf8_lossy(input_chirho).to_string();
    let completion_chirho = LlmCompletionV1Chirho { text_chirho };
    match validate_build_params_impl_fn_chirho(&completion_chirho) {
        Ok(deploy_request_chirho) => serde_json::to_vec(&deploy_request_chirho)
            .unwrap_or_else(|_e_chirho| cairn_node_sdk_chirho::json_error_bytes_chirho()),
        // Invalid model output -> the SDK error envelope, which is not a valid deploy request; the
        // deploy door's request decode / required-field / slug validation rejects it (fail closed).
        Err(_reason_chirho) => cairn_node_sdk_chirho::json_error_bytes_chirho(),
    }
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(validate_chirho, validate_impl_chirho);
