// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16 (KJV)

const VIEWER_STATE_READ_REQUEST_CHIRHO: &[u8] = br#"{"schema_chirho":"viewer-state-request-v1-chirho","action_chirho":"read-chirho","key_chirho":"workspace-name-chirho"}"#;

/// Builds a fixed logical-key request. The host derives the app and signed-in viewer scopes.
pub fn build_viewer_state_read_chirho() -> &'static [u8] {
    VIEWER_STATE_READ_REQUEST_CHIRHO
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn request_cannot_select_an_app_or_viewer_chirho() {
        let request_chirho = std::str::from_utf8(build_viewer_state_read_chirho()).unwrap();
        assert!(request_chirho.contains("\"action_chirho\":\"read-chirho\""));
        assert!(request_chirho.contains("\"key_chirho\":\"workspace-name-chirho\""));
        assert!(!request_chirho.contains("principal_chirho"));
        assert!(!request_chirho.contains("app_chirho"));
    }
}
