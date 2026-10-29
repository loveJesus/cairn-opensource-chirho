// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Contact example smoke report and wire evidence types.

use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{app_source_manifest_chirho, privacy_chirho};
use serde::Serialize;
use std::collections::BTreeMap;

pub const CONTACT_EXAMPLE_SMOKE_REPORT_SCHEMA_CHIRHO: &str =
    "contact-example-smoke-report-v3-chirho";
pub(super) const CONTACT_EXAMPLE_WIRE_EVIDENCE_SCHEMA_CHIRHO: &str =
    "contact-example-wire-evidence-v1-chirho";
pub(super) const CONTACT_EXAMPLE_REVEAL_EVIDENCE_SCHEMA_CHIRHO: &str =
    "contact-example-reveal-evidence-v1-chirho";
pub(super) const CONTACT_EXAMPLE_PRIVATE_BODY_EVIDENCE_SCHEMA_CHIRHO: &str =
    "contact-example-private-body-evidence-v1-chirho";
pub(super) const CONTACT_EXAMPLE_PERSISTED_EVIDENCE_SCHEMA_CHIRHO: &str =
    "contact-example-persisted-evidence-v1-chirho";
pub const CONTACT_EXAMPLE_SERVED_READ_POSTURE_CHIRHO: &str =
    "served-refused-no-ledger-source-chirho";
pub const CONTACT_EXAMPLE_OPERATOR_READ_POSTURE_CHIRHO: &str = "operator-direct-read-chirho";

#[derive(Clone, Debug, Serialize)]
pub struct ContactExampleSmokeReportChirho {
    pub schema_chirho: &'static str,
    pub manifest_source_chirho: String,
    pub manifest_hash_chirho: HashChirho,
    pub manifest_template_owner_chirho: String,
    pub root_scope_chirho: String,
    pub app_chirho: String,
    pub owner_chirho: String,
    pub server_chirho: String,
    pub deploy_chirho: app_source_manifest_chirho::AppSourceDeployReportChirho,
    pub page_chirho: ContactExampleWireEvidenceChirho,
    pub submit_chirho: ContactExampleWireEvidenceChirho,
    pub list_refresh_chirho: ContactExampleWireEvidenceChirho,
    pub read_evidence_chirho: Vec<ContactExampleReadEvidenceChirho>,
    pub missing_owner_session_chirho: ContactExampleWireEvidenceChirho,
    pub app_state_chirho: ContactExampleWireEvidenceChirho,
    pub reveal_chirho: ContactExampleRevealEvidenceChirho,
    pub private_body_chirho: ContactExamplePrivateBodyEvidenceChirho,
    pub persisted_chirho: ContactExamplePersistedEvidenceChirho,
    pub privacy_verify_chirho: privacy_chirho::PrivacyVerifyReportChirho,
    pub privacy_scan_chirho: privacy_chirho::PrivacyScanReportChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "path_posture_chirho")]
pub enum ContactExampleReadEvidenceChirho {
    #[serde(rename = "served-refused-no-ledger-source-chirho")]
    ServedRefusedNoLedgerSourceChirho {
        route_chirho: String,
        status_chirho: u16,
        refusal_chirho: String,
        zero_effect_volatile_billing_mutation_chirho: bool,
    },
    #[serde(rename = "operator-direct-read-chirho")]
    OperatorDirectReadChirho {
        operation_chirho: String,
        row_count_chirho: usize,
    },
}

impl ContactExampleReadEvidenceChirho {
    pub fn path_posture_chirho(&self) -> &'static str {
        match self {
            Self::ServedRefusedNoLedgerSourceChirho { .. } => {
                CONTACT_EXAMPLE_SERVED_READ_POSTURE_CHIRHO
            }
            Self::OperatorDirectReadChirho { .. } => CONTACT_EXAMPLE_OPERATOR_READ_POSTURE_CHIRHO,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ContactExampleWireEvidenceChirho {
    pub schema_chirho: &'static str,
    pub method_chirho: String,
    pub path_chirho: String,
    pub status_chirho: u16,
    pub content_type_chirho: Option<String>,
    pub body_bytes_chirho: usize,
    pub body_chirho: HashChirho,
    pub pii_needles_absent_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ContactExampleRevealEvidenceChirho {
    pub schema_chirho: &'static str,
    pub method_chirho: String,
    pub path_chirho: String,
    pub status_chirho: u16,
    pub body_bytes_chirho: usize,
    pub body_chirho: HashChirho,
    pub contains_expected_private_body_chirho: bool,
    pub access_records_chirho: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ContactExamplePrivateBodyEvidenceChirho {
    pub schema_chirho: &'static str,
    pub request_bytes_chirho: usize,
    pub request_chirho: HashChirho,
    pub raw_body_absent_from_cas_chirho: bool,
    pub private_blob_records_chirho: usize,
    pub private_blob_roundtrip_verified_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ContactExamplePersistedEvidenceChirho {
    pub schema_chirho: &'static str,
    pub contact_key_chirho: String,
    pub versioned_view_chirho: u64,
    pub query_rows_chirho: usize,
    pub persistent_effect_records_chirho: usize,
    pub volatile_effect_records_chirho: usize,
    pub volatile_effect_objects_chirho: usize,
    pub contact_safe_surfaces_scanned_chirho: usize,
    pub contact_safe_surfaces_pii_free_chirho: bool,
}

#[derive(Clone, Debug)]
pub(super) struct HttpSmokeResponseChirho {
    pub(super) status_chirho: u16,
    pub(super) headers_chirho: BTreeMap<String, String>,
    pub(super) body_chirho: Vec<u8>,
}

pub(super) struct ContactExampleWireRunChirho {
    pub(super) server_chirho: String,
    pub(super) page_chirho: ContactExampleWireEvidenceChirho,
    pub(super) submit_chirho: ContactExampleWireEvidenceChirho,
    pub(super) list_refresh_chirho: ContactExampleWireEvidenceChirho,
    pub(super) read_evidence_chirho: Vec<ContactExampleReadEvidenceChirho>,
    pub(super) missing_owner_session_chirho: ContactExampleWireEvidenceChirho,
    pub(super) app_state_chirho: ContactExampleWireEvidenceChirho,
    pub(super) reveal_chirho: ContactExampleRevealEvidenceChirho,
    pub(super) contact_key_chirho: String,
}
