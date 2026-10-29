// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};

/// The raw spend form post as it arrives from the world (untrusted). The item is a bounded label;
/// the concurrency token is an opaque keyed fingerprint supplied by the operator-seeded row.
/// Extra flat runtime-context or caller fields are discarded; Descriptor-D receives its verified
/// request context through a separate runtime port, and a source guard pins this typed field set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormPostV1Chirho {
    #[serde(default)]
    pub item_chirho: String,
    #[serde(default)]
    pub concurrency_token_chirho: String,
}
