// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Per-app API descriptor: an agent-readable map of a deployed app's HTTP routes, each with its input mode and plain-language capability verdict — the source of truth that generated docs and an MCP tool manifest both derive from.

use cairn_capability_chirho::capability_plain_chirho;
use serde::{Deserialize, Serialize};

/// One callable route of an app: its HTTP path, how its request body is handled, the response
/// content type (when pinned), and exactly what running it can do to the world.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRouteDescriptorChirho {
    /// The served HTTP path, e.g. `/app-chirho/cardshop` (default surface) or
    /// `/app-chirho/cardshop/orders` (a named route).
    pub path_chirho: String,
    /// The route name, or None for the app's default/root surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_chirho: Option<String>,
    /// `"plain"` (the body is passed through) or `"private-encrypted"` (the body is sealed as a
    /// private blob before the DAG ever sees it — for PII).
    pub input_mode_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_content_type_chirho: Option<String>,
    pub capability_summary_chirho: capability_plain_chirho::CapabilitySummaryChirho,
}

/// The whole app's API surface, agent-readable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDescriptorChirho {
    pub schema_chirho: String,
    pub app_chirho: String,
    pub active_chirho: bool,
    pub route_count_chirho: usize,
    pub routes_chirho: Vec<AppRouteDescriptorChirho>,
}
