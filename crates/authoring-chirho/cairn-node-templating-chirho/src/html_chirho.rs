// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The HTML response value a render node produces (already escaped; safe to emit). The one shared
//! type that replaces the per-app `HtmlPartialV1Chirho` copies.

use serde::{Deserialize, Serialize};

/// A rendered HTML partial. A render guest returns `html_chirho` as the response bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtmlPartialV1Chirho {
    pub html_chirho: String,
}

impl HtmlPartialV1Chirho {
    /// Build a partial from markup.
    pub fn new_chirho(html_chirho: impl Into<String>) -> Self {
        Self {
            html_chirho: html_chirho.into(),
        }
    }

    /// The markup as response bytes (what a render guest returns over the bytes ABI).
    pub fn into_bytes_chirho(self) -> Vec<u8> {
        self.html_chirho.into_bytes()
    }
}
