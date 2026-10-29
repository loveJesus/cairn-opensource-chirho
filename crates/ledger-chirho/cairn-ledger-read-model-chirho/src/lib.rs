// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pure CF4 read-model contracts.
//!
//! A projection is disposable, derived, and never money authority. The authoritative source remains
//! the verified signed ledger prefix and issuer aggregate. This crate defines a content-addressed
//! descriptor, privacy-floor/source admission checks, and fail-closed follower-read classification.
//! It has no storage, network, clock, signer, or write capability. Production adapters verify source
//! signatures and execute the pinned pure fold; the conservation monitor independently verifies the
//! resulting views before treating them as evidence.

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

// The module tree is GROUPED into four single-purpose dirs (the recorded loan's repayment) while
// every public module keeps its flat crate path via #[path] — zero consumer changes anywhere.
#[path = "feed_group_chirho/account_net_chirho.rs"]
pub mod account_net_chirho;
#[path = "registry_group_chirho/descriptor_chirho.rs"]
pub mod descriptor_chirho;
#[path = "feed_group_chirho/feeder_chirho.rs"]
pub mod feeder_chirho;
#[path = "serve_group_chirho/follower_chirho.rs"]
pub mod follower_chirho;
#[path = "feed_group_chirho/heartbeat_chirho.rs"]
pub mod heartbeat_chirho;
#[path = "evidence_group_chirho/localphaseb_evidence_chirho.rs"]
pub mod localphaseb_evidence_chirho;
#[path = "feed_group_chirho/merge_chirho.rs"]
pub mod merge_chirho;
#[path = "feed_group_chirho/merge_feeder_chirho.rs"]
pub mod merge_feeder_chirho;
#[path = "serve_group_chirho/merge_serving_chirho.rs"]
pub mod merge_serving_chirho;
#[path = "evidence_group_chirho/monitor_chirho.rs"]
pub mod monitor_chirho;
#[path = "evidence_group_chirho/publication_chirho.rs"]
pub mod publication_chirho;
#[path = "registry_group_chirho/registry_chirho.rs"]
pub mod registry_chirho;
#[path = "serve_group_chirho/serving_chirho.rs"]
pub mod serving_chirho;
#[path = "registry_group_chirho/source_registry_chirho.rs"]
pub mod source_registry_chirho;
#[cfg(test)]
#[path = "evidence_group_chirho/test_support_chirho.rs"]
pub(crate) mod test_support_chirho;

pub use account_net_chirho::{
    account_net_projection_fold_ref_chirho, account_net_projection_page_chirho,
    account_net_projection_row_chirho, account_net_source_schema_ref_chirho,
    canonical_account_net_projection_view_chirho,
    parse_canonical_account_net_projection_view_chirho, AccountNetProjectionFoldChirho,
    AccountNetProjectionPageSliceChirho, AccountNetProjectionRowChirho,
    AccountNetProjectionViewChirho, ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO,
    ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO,
};
pub use descriptor_chirho::{
    derive_projection_privacy_evidence_ref_chirho, parse_canonical_projection_descriptor_chirho,
    projection_descriptor_bytes_chirho, projection_descriptor_digest_chirho,
    validate_projection_descriptor_against_verified_sources_chirho,
    validate_projection_descriptor_chirho, verify_projection_descriptor_chirho,
    ProjectionCostClassChirho, ProjectionDescriptorChirho, ProjectionReadPolicyChirho,
    ProjectionRebuildLawChirho, ProjectionSourceBindingChirho, StalenessContractChirho,
    VerifiedProjectionDescriptorChirho, VerifiedProjectionSourceChirho,
    PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
pub use follower_chirho::{
    classify_follower_read_chirho, FollowerReadRefusalChirho, ProjectionReadOutcomeChirho,
    ProjectionWatermarkChirho, PublishedProjectionViewChirho, VerifiedProjectionReadCutChirho,
    VerifiedProjectionSourceHeadChirho,
};
pub use merge_chirho::{
    canonical_projection_merge_chirho, CanonicalProjectionMergeChirho, ProjectionMergeEventChirho,
    ProjectionMergeKeyChirho, ProjectionMergeSourcePrefixChirho,
    PROJECTION_MERGE_PROTOCOL_V1_CHIRHO,
};

#[cfg(test)]
#[path = "evidence_group_chirho/model_f2_chirho.rs"]
mod model_f2_chirho;
#[cfg(test)]
#[path = "evidence_group_chirho/model_f_chirho.rs"]
mod model_f_chirho;
#[cfg(test)]
#[path = "evidence_group_chirho/tests_chirho.rs"]
mod tests_chirho;
