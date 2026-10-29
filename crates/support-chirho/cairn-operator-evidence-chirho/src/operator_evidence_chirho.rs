// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Provides fixed redaction labels for shareable operator evidence reports.

use std::path::Path;

pub const LOCAL_ROOT_REDACTED_CHIRHO: &str = "local-root-redacted-chirho";
pub const MANIFEST_SOURCE_REDACTED_CHIRHO: &str = "path-redacted-manifest-hash-bound-chirho";
pub const OVERCAP_MANIFEST_SOURCE_REDACTED_CHIRHO: &str =
    "path-redacted-overcap-manifest-hash-bound-chirho";
pub const UNDECLARED_EFFECT_MANIFEST_SOURCE_REDACTED_CHIRHO: &str =
    "path-redacted-undeclared-effect-manifest-hash-bound-chirho";
pub const BRIEF_SOURCE_REDACTED_CHIRHO: &str = "path-redacted-brief-hash-bound-chirho";

pub fn redacted_local_root_scope_chirho(_root_chirho: &Path) -> String {
    LOCAL_ROOT_REDACTED_CHIRHO.to_string()
}

pub fn redacted_manifest_source_chirho(_manifest_path_chirho: &Path) -> String {
    MANIFEST_SOURCE_REDACTED_CHIRHO.to_string()
}

pub fn redacted_overcap_manifest_source_chirho(_manifest_path_chirho: &Path) -> String {
    OVERCAP_MANIFEST_SOURCE_REDACTED_CHIRHO.to_string()
}

pub fn redacted_undeclared_effect_manifest_source_chirho(_manifest_path_chirho: &Path) -> String {
    UNDECLARED_EFFECT_MANIFEST_SOURCE_REDACTED_CHIRHO.to_string()
}

pub fn redacted_brief_source_chirho(_brief_path_chirho: &Path) -> String {
    BRIEF_SOURCE_REDACTED_CHIRHO.to_string()
}
