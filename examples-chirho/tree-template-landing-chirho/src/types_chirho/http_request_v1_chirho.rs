// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};

use crate::types_chirho::app_params_landing_v1_chirho::AppParamsLandingV1Chirho;

/// The raw HTTP request as it arrives at the template landing dag's surface, plus the injected
/// template content. It types the surface boundary so the dag has a real input port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestV1Chirho {
    #[serde(default)]
    pub path_chirho: String,
    // Opt-in: session-aware serving injects the signed-in principal here (None if anonymous).
    #[serde(default)]
    pub user_principal_chirho: Option<String>,
    // Runtime app-params injection can populate this from a signed owner-scoped record. The default
    // request uses reviewed public source-dictionary copy instead.
    #[serde(default)]
    pub app_params_chirho: Option<AppParamsLandingV1Chirho>,
}

impl Default for HttpRequestV1Chirho {
    fn default() -> Self {
        Self {
            path_chirho: String::new(),
            user_principal_chirho: None,
            app_params_chirho: Some(
                crate::content_chirho::landing_public_copy_chirho::landing_public_copy_chirho(),
            ),
        }
    }
}
