// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};

/// A validated contact message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageV1Chirho {
    pub name_chirho: String,
    pub body_chirho: String,
}
