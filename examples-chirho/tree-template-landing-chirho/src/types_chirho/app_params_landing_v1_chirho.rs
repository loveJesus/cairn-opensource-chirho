// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};

/// The content the landing-page template renders from. This is the DATA the AI app-builder will
/// later produce; the render itself stays fixed, vetted code. Every field is optional/defaulted so a
/// partial or empty params object still parses (the render falls back to a safe placeholder when the
/// business name is missing).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppParamsLandingV1Chirho {
    #[serde(default)]
    pub business_name_chirho: String,
    #[serde(default)]
    pub tagline_chirho: String,
    #[serde(default)]
    pub features_chirho: Vec<TemplateFeatureChirho>,
    #[serde(default)]
    pub contact_chirho: String,
}

/// One feature/highlight card on the landing page (a heading + a short body).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateFeatureChirho {
    #[serde(default)]
    pub title_chirho: String,
    #[serde(default)]
    pub body_chirho: String,
}
