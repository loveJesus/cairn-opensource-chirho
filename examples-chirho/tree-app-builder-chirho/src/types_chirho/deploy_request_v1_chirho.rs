// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};

use crate::types_chirho::app_params_landing_v1_chirho::AppParamsLandingV1Chirho;

/// The request the blessed template-deploy door consumes: which vetted template `schema_chirho` to
/// deploy, a URL-safe `slug_chirho` for the built app, a content-derived `idem_key_chirho` so an
/// identical build is idempotent, and the strict-validated `params_chirho` the template renders from.
/// The pure `validate_build_params` node only ever produces this on a fully-valid completion; on
/// invalid model output it produces a non-deploy error envelope instead, so the door fails closed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployRequestV1Chirho {
    #[serde(default)]
    pub schema_chirho: String,
    #[serde(default)]
    pub slug_chirho: String,
    #[serde(default)]
    pub idem_key_chirho: String,
    #[serde(default)]
    pub params_chirho: AppParamsLandingV1Chirho,
}
