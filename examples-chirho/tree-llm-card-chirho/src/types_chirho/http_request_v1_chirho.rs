// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use serde::{Deserialize, Serialize};

/// The raw HTTP request as it reaches the served-LLM card DAG's surface. It types the surface
/// boundary so the DAG has a real input port, and carries the free-text business
/// `description_chirho` the card turns into a drafted landing page. `render_form_chirho` ignores it
/// (the empty-body GET renders the same static form for everyone).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestV1Chirho {
    #[serde(default)]
    pub path_chirho: String,
    // Opt-in: session-aware serving injects the signed-in principal here (None if anonymous).
    #[serde(default)]
    pub user_principal_chirho: Option<String>,
    // The free-text business description the served LLM drafts a landing page from.
    #[serde(default)]
    pub description_chirho: String,
}
