// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16 (KJV)

use crate::generated_chirho::render_workspace_state_chirho::render_workspace_state_chirho as render_workspace_state_template_chirho;
use crate::types_chirho::viewer_state_response_v1_chirho::ViewerStateResponseV1Chirho;
use crate::types_chirho::workspace_state_page_v1_chirho::WorkspaceStatePageV1Chirho;
use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use cairn_node_templating_chirho::HtmlPartialV1Chirho;

const VIEWER_STATE_RESPONSE_SCHEMA_CHIRHO: &str = "viewer-state-response-v2-chirho";
const WORKSPACE_NAME_KEY_CHIRHO: &str = "workspace-name-chirho";

pub fn render_workspace_state_chirho(input_chirho: &[u8]) -> HtmlPartialV1Chirho {
    let model_chirho = workspace_state_page_chirho(input_chirho);
    render_workspace_state_template_chirho(&model_chirho)
}

fn workspace_state_page_chirho(input_chirho: &[u8]) -> WorkspaceStatePageV1Chirho {
    let Ok(response_chirho) = serde_json::from_slice::<ViewerStateResponseV1Chirho>(input_chirho)
    else {
        return unavailable_page_chirho();
    };
    if response_chirho.schema_chirho != VIEWER_STATE_RESPONSE_SCHEMA_CHIRHO
        || response_chirho.key_chirho != WORKSPACE_NAME_KEY_CHIRHO
    {
        return unavailable_page_chirho();
    }
    let Some(current_chirho) = response_chirho.current_chirho else {
        return WorkspaceStatePageV1Chirho::default();
    };
    let Ok(value_chirho) = BASE64_CHIRHO.decode(current_chirho.value_base64_chirho) else {
        return unavailable_page_chirho();
    };
    let Ok(workspace_name_chirho) = String::from_utf8(value_chirho) else {
        return unavailable_page_chirho();
    };
    let workspace_name_chirho = workspace_name_chirho.trim().to_string();
    if workspace_name_chirho.is_empty() {
        return unavailable_page_chirho();
    }
    WorkspaceStatePageV1Chirho {
        workspace_name_chirho: Some(workspace_name_chirho),
        current_version_chirho: Some(current_chirho.version_chirho),
        unavailable_chirho: false,
    }
}

fn unavailable_page_chirho() -> WorkspaceStatePageV1Chirho {
    WorkspaceStatePageV1Chirho {
        unavailable_chirho: true,
        ..WorkspaceStatePageV1Chirho::default()
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn template_escapes_private_workspace_name_chirho() {
        let response_chirho = br#"{"schema_chirho":"viewer-state-response-v2-chirho","key_chirho":"workspace-name-chirho","current_chirho":{"version_chirho":3,"value_base64_chirho":"PHNjcmlwdD5ubzwvc2NyaXB0Pg=="},"history_chirho":[]}"#;
        let page_chirho = render_workspace_state_chirho(response_chirho).html_chirho;
        assert!(page_chirho.contains("script"));
        assert!(page_chirho.contains("no"));
        assert!(!page_chirho.contains("<script>"));
        assert!(page_chirho.contains("Version 3"));
    }
}
