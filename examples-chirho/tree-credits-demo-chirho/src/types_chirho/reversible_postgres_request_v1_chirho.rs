// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Guest-side mirror of the strict reversible-PostgreSQL request wire. The runtime remains the
//! authority and exact-parses these bytes before intent derivation; this type lets app-authored pure
//! code construct only the reviewed fixed-coordinate delete shape.
//!
//! Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.

use serde::{Deserialize, Serialize};

pub const REVERSIBLE_POSTGRES_REQUEST_SCHEMA_CHIRHO: &str = "reversible-postgres-request-v1-chirho";
pub const FIXED_SPEND_ITEM_CHIRHO: &str = "render-run-chirho";
pub const FIXED_SUBJECT_CHIRHO: &str =
    "81b8078f2e6771d23a2f3ff001d4229370708ea97389ba5ba3372b300cbf8508";
pub const FIXED_ROW_KEY_CHIRHO: &str =
    "62c2bd5bd145a1a00e980f80e14f30cd61da58755a4ccb17b64dbe407a628ef4";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum ExpectedPostgresStateV1Chirho {
    #[serde(rename = "keyed-fingerprint-chirho")]
    KeyedFingerprintChirho { fingerprint_chirho: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum DesiredPostgresStateV1Chirho {
    #[serde(rename = "absent-chirho")]
    AbsentChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReversiblePostgresRequestV1Chirho {
    pub schema_chirho: String,
    pub subject_chirho: String,
    pub row_key_chirho: String,
    pub expected_before_chirho: ExpectedPostgresStateV1Chirho,
    pub desired_chirho: DesiredPostgresStateV1Chirho,
}

impl ReversiblePostgresRequestV1Chirho {
    pub fn canonical_bytes_chirho(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("fixed reversible-Postgres request serializes")
    }
}
