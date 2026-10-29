// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};

/// What the blessed template-deploy door returns once it has deployed the validated params into the
/// vetted template: where the built app lives and who owns it. `params_chirho` here is a content
/// HASH of the deployed params (not the params themselves), so the response stays a small, safe
/// receipt. The pure `render_build_result` node turns this into the "your app is live" page.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployResponseV1Chirho {
    #[serde(default)]
    pub schema_chirho: String,
    #[serde(default)]
    pub app_chirho: String,
    #[serde(default)]
    pub url_chirho: String,
    #[serde(default)]
    pub owner_principal_chirho: String,
    #[serde(default)]
    pub user_principal_chirho: String,
    #[serde(default)]
    pub template_id_chirho: String,
    #[serde(default)]
    pub display_slug_chirho: String,
    // A content hash of the deployed params (not the params themselves).
    #[serde(default)]
    pub params_chirho: String,
    #[serde(default)]
    pub deploy_record_seq_chirho: u64,
}
