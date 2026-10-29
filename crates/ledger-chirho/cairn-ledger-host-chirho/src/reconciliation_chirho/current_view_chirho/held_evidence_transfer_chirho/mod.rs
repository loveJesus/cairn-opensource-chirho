// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Bounded winner-to-held transfer of adoption input evidence.
//!
//! This module carries and independently reverifies immutable evidence only. It cannot install a
//! journal branch, move a ref, compensate an effect, adopt a winner view, or re-enable writes.

mod account_net_composition_chirho;
mod contract_chirho;
mod held_store_chirho;
#[path = "read_only_branch_chirho/mod.rs"]
mod read_only_branch_chirho;

pub use account_net_composition_chirho::{
    Gd7AccountNetCompositionRefusalChirho, VerifiedGd7AccountNetCompositionChirho,
};
pub use contract_chirho::{
    build_gd7_winner_evidence_manifest_chirho, fetch_gd7_winner_evidence_page_chirho,
    gd7_held_evidence_transfer_identity_digest_chirho, verify_gd7_winner_evidence_manifest_chirho,
    verify_gd7_winner_evidence_page_transfer_chirho, Gd7HeldEvidenceTransferIdentityChirho,
    Gd7WinnerEvidenceFamilyChirho, Gd7WinnerEvidenceManifestChirho,
    Gd7WinnerEvidencePageGrantChirho, Gd7WinnerEvidencePageTransferChirho,
    Gd7WinnerEvidenceTransferRefusalChirho, GD7_WINNER_EVIDENCE_MANIFEST_SCHEMA_V1_CHIRHO,
    GD7_WINNER_EVIDENCE_PAGE_GRANT_SCHEMA_V1_CHIRHO, MAX_GD7_WINNER_EVIDENCE_MANIFEST_BYTES_CHIRHO,
    MAX_GD7_WINNER_EVIDENCE_PAGE_GRANT_BYTES_CHIRHO,
};
pub use held_store_chirho::{
    gd7_held_evidence_transfer_checkpoint_path_chirho, gd7_held_evidence_transfer_head_path_chirho,
    ActiveGd7HeldEvidenceTransferChirho, Gd7HeldEvidenceTransferCheckpointChirho,
    Gd7HeldEvidenceTransferHeadChirho, Gd7HeldEvidenceTransferPhaseChirho,
    Gd7HeldEvidenceTransferStoreChirho, Gd7HeldEvidenceTransferStoreRefusalChirho,
    GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_SCHEMA_V1_CHIRHO,
    GD7_HELD_EVIDENCE_TRANSFER_HEAD_SCHEMA_V1_CHIRHO,
    MAX_GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_BYTES_CHIRHO,
    MAX_GD7_HELD_EVIDENCE_TRANSFER_HEAD_BYTES_CHIRHO,
};
pub use read_only_branch_chirho::{
    gd7_read_only_branch_checkpoint_path_chirho, gd7_read_only_branch_head_path_chirho,
    gd7_read_only_branch_prefix_page_path_chirho, gd7_read_only_branch_prefix_root_path_chirho,
    ActiveGd7ReadOnlyBranchChirho, Gd7ReadOnlyBranchCheckpointChirho, Gd7ReadOnlyBranchHeadChirho,
    Gd7ReadOnlyBranchPrefixRootChirho, Gd7ReadOnlyBranchRefusalChirho,
    PreparedGd7ReadOnlyBranchChirho, VerifiedGd7ReadOnlyBranchChirho,
    GD7_READ_ONLY_BRANCH_CHECKPOINT_SCHEMA_V1_CHIRHO, GD7_READ_ONLY_BRANCH_HEAD_SCHEMA_V1_CHIRHO,
    GD7_READ_ONLY_BRANCH_PREFIX_ROOT_SCHEMA_V1_CHIRHO,
    MAX_GD7_READ_ONLY_BRANCH_CHECKPOINT_BYTES_CHIRHO, MAX_GD7_READ_ONLY_BRANCH_HEAD_BYTES_CHIRHO,
    MAX_GD7_READ_ONLY_BRANCH_PREFIX_PAGE_BYTES_CHIRHO,
    MAX_GD7_READ_ONLY_BRANCH_PREFIX_ROOT_BYTES_CHIRHO,
};

#[cfg(test)]
mod tests_chirho;
