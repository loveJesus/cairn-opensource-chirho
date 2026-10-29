// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};

/// The raw HTTP request as it arrives (the static landing page ignores it; it types the surface
/// boundary so the dag has a real input port).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestV1Chirho {
    #[serde(default)]
    pub path_chirho: String,
}
