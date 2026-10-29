// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};

/// The raw HTTP request as it arrives at the app-builder dag's surface. It types the surface
/// boundary so the dag has a real input port, and carries the free-text business `description_chirho`
/// the builder turns into a deployed app.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestV1Chirho {
    #[serde(default)]
    pub path_chirho: String,
    // Opt-in: session-aware serving injects the signed-in principal here (None if anonymous). The
    // deploy door owns the built app to this principal.
    #[serde(default)]
    pub user_principal_chirho: Option<String>,
    // The free-text business description the model turns into landing params.
    #[serde(default)]
    pub description_chirho: String,
}
