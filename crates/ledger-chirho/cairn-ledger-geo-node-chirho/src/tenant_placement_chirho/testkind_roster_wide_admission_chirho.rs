// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Explicit compatibility admission for the separate CF7 test-kind drill binary.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/tenant-placement-authority-chirho.md`.

use super::{
    serve_resident_gd7_voter_geo_node_with_admission_chirho,
    A6GeoResidentAuthorityCompositionChirho, GeoVoterAdmissionPostureChirho,
    GeoVoterPlacementAdmissionChirho, GeoVoterStartupOwnershipChirho,
};
use anyhow::Result;
use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_ledger_host_chirho::ResidentEffectJournalHandleChirho;
use cairn_serve_runtime_chirho::{
    LedgerHostProjectionReadPortChirho, SharedLedgerHostPostgresEffectRuntimeChirho,
};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;

/// Admit roster-wide membership only for the feature-gated, separately packaged test-kind drill.
pub fn serve_testkind_roster_wide_gd7_voter_geo_node_chirho(
    cluster_config_path_chirho: &Path,
    ledger_config_path_chirho: &Path,
    expected_ledger_config_digest_chirho: &str,
    selected_root_chirho: &Path,
    open_resident_chirho: impl FnOnce(
        &A6GeoResidentAuthorityCompositionChirho,
        &Path,
        &Path,
        &LedgerHostConfigChirho,
    ) -> Result<ResidentEffectJournalHandleChirho>,
    start_local_owner_sidecar_chirho: impl FnOnce(
        &Path,
        Arc<LedgerHostProjectionReadPortChirho>,
        SharedLedgerHostPostgresEffectRuntimeChirho,
        Arc<AtomicBool>,
    ) -> Result<Option<JoinHandle<Result<()>>>>,
) -> Result<()> {
    serve_resident_gd7_voter_geo_node_with_admission_chirho(
        cluster_config_path_chirho,
        ledger_config_path_chirho,
        expected_ledger_config_digest_chirho,
        selected_root_chirho,
        GeoVoterAdmissionPostureChirho::new_chirho(
            GeoVoterPlacementAdmissionChirho::ExplicitTestkindRosterWideChirho,
            GeoVoterStartupOwnershipChirho::FirstKnownOwnerChirho,
        ),
        open_resident_chirho,
        start_local_owner_sidecar_chirho,
    )
}
