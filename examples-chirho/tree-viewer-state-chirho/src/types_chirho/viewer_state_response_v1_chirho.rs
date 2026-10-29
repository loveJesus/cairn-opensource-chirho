// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16 (KJV)

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ViewerStateVersionV1Chirho {
    pub version_chirho: u64,
    pub value_base64_chirho: String,
}

#[derive(Debug, Deserialize)]
pub struct ViewerStateResponseV1Chirho {
    pub schema_chirho: String,
    pub key_chirho: String,
    #[serde(default)]
    pub current_chirho: Option<ViewerStateVersionV1Chirho>,
}
