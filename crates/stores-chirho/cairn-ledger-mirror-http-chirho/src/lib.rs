// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Private-mesh adapter for mirror-gated F1 ledger appends.
//!
//! The adapter carries one already-admitted canonical signed ledger line. It owns no ledger signer,
//! append authority, effect provider, or served mutation entrypoint. The receiver stores only in an
//! inert mirror namespace and signs a receipt after native durability.

mod client_chirho;
mod composition_chirho;
mod family_chirho;
mod recovery_chirho;
mod server_chirho;
mod store_chirho;

pub const LEDGER_MIRROR_PREPARE_PATH_CHIRHO: &str = "/ledger-mirror-chirho/v1/prepare";
pub const LEDGER_MIRROR_FINALIZE_PATH_CHIRHO: &str = "/ledger-mirror-chirho/v1/finalize";
pub const LEDGER_MIRROR_RECOVERY_HEAD_PATH_CHIRHO: &str = "/ledger-mirror-chirho/v1/recovery-head";
pub const LEDGER_MIRROR_ORDINARY_TERM_ACCEPTANCE_PATH_CHIRHO: &str =
    "/ledger-mirror-chirho/v1/ordinary-term-acceptance";
pub const LEDGER_MIRROR_PREFIX_BEGIN_PATH_CHIRHO: &str =
    "/ledger-mirror-chirho/v1/verified-prefix-begin";
pub const LEDGER_MIRROR_PREFIX_PAGE_PATH_CHIRHO: &str =
    "/ledger-mirror-chirho/v1/verified-prefix-page";
pub const LEDGER_MIRROR_PREFIX_SEAL_PATH_CHIRHO: &str =
    "/ledger-mirror-chirho/v1/verified-prefix-seal";

pub use composition_chirho::{
    compose_ledger_append_mirror_chirho, read_live_ledger_mirror_recovery_head_receipt_chirho,
    LedgerAppendMirrorCompositionChirho, LedgerMirrorLiveHeadReadRefusalChirho,
    LedgerMirrorPeerEndpointChirho,
};
pub use family_chirho::LedgerMirrorJournalVerifierBindingChirho;
pub use recovery_chirho::{
    ledger_mirror_live_head_bound_verdict_bytes_chirho,
    ledger_mirror_live_head_bound_verdict_chirho, ledger_mirror_live_head_report_bytes_chirho,
    ledger_mirror_live_head_report_chirho,
    verify_ledger_mirror_live_head_bound_verdict_bytes_chirho,
    LedgerMirrorLiveHeadBoundVerdictChirho, LedgerMirrorLiveHeadBoundVerdictRefusalChirho,
    LedgerMirrorLiveHeadReportChirho, LedgerMirrorLiveHeadReportRefusalChirho,
    LedgerMirrorLiveHeadReportStatusChirho, LedgerMirrorRecoveryHeadReceiptChirho,
    VerifiedLedgerMirrorRecoveryHeadPairChirho,
    LEDGER_MIRROR_LIVE_HEAD_BOUND_VERDICT_SCHEMA_V1_CHIRHO,
    LEDGER_MIRROR_LIVE_HEAD_REPORT_SCHEMA_V1_CHIRHO,
    MAX_LEDGER_MIRROR_LIVE_HEAD_BOUND_VERDICT_BYTES_CHIRHO,
    MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO,
};

#[cfg(test)]
mod tests_chirho;
