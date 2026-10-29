// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The ONE place any crate outside the resident actor names the winner-side E-B
//! compensation-provider door — the test-kind opener that hands a synthetic reporting-only provider
//! through it. Guard A allows exactly this file (plus the two door definitions) to name the door.

use crate::reporting_provider_chirho::TestkindSettlementReportingProviderChirho;
use anyhow::Result;
use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_ledger_geo_node_chirho::a6_authority_composition_chirho::A6GeoResidentAuthorityCompositionChirho;
use cairn_ledger_host_chirho::{
    open_resident_effect_journal_handle_with_shared_elector_and_gd7_compensation_provider_chirho,
    Gd7CompensationProviderAdapterChirho, ResidentActorServiceCompositionChirho,
    ResidentEffectJournalHandleChirho, TenantMigrationCapacityAdmissionCompositionChirho,
};
use cairn_ledger_log_chirho::recovery_mirror_chirho::LedgerMirrorRuntimePortsChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use std::path::Path;
use std::sync::Arc;

/// Open the WINNER's resident actor through the E-B winner-side compensation-provider door with a
/// caller-supplied reporting-only provider.
///
/// The elector MUST be the exact shared cluster elector that carries the winner's accepted handoff
/// marker: E-B is the shared-elector door precisely so the winner's append freeze (an in-memory
/// marker on that elector) is visible to the resident actor. The provider only REPORTS a
/// settlement; no code on this path moves real money.
pub fn open_testkind_winner_resident_with_reporting_provider_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
    elector_chirho: &Arc<RaftWriterElectorChirho>,
    mirror_runtime_chirho: Option<LedgerMirrorRuntimePortsChirho>,
    capacity_admission_chirho: Option<TenantMigrationCapacityAdmissionCompositionChirho>,
    provider_chirho: Box<dyn Gd7CompensationProviderAdapterChirho + Send>,
) -> Result<ResidentEffectJournalHandleChirho> {
    open_resident_effect_journal_handle_with_shared_elector_and_gd7_compensation_provider_chirho(
        selected_root_chirho,
        config_path_chirho,
        config_chirho,
        elector_chirho,
        ResidentActorServiceCompositionChirho::with_gd7_compensation_provider_chirho(
            mirror_runtime_chirho,
            None,
            capacity_admission_chirho,
            provider_chirho,
        ),
    )
}

/// The resident opener the test-kind BINARY injects into
/// [`cairn_ledger_geo_node_chirho::serve_resident_gd7_voter_geo_node_with_resident_opener_chirho`].
///
/// It builds a fresh synthetic reporting-only provider and reaches E-B through the composition's own
/// shared elector — the exact elector the geo-node winner startup assembled — so the winner's freeze
/// marker is honored. The production geo node passes the provider-less default opener instead; this
/// opener is the only thing that turns the shipped voter startup into a completing test-kind node.
pub fn testkind_resident_opener_chirho(
    authority_composition_chirho: &A6GeoResidentAuthorityCompositionChirho,
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
) -> Result<ResidentEffectJournalHandleChirho> {
    open_testkind_winner_resident_with_reporting_provider_chirho(
        selected_root_chirho,
        config_path_chirho,
        config_chirho,
        authority_composition_chirho.elector_chirho(),
        authority_composition_chirho.mirror_runtime_chirho(),
        authority_composition_chirho.capacity_admission_chirho(),
        Box::new(TestkindSettlementReportingProviderChirho::new_chirho()),
    )
}
