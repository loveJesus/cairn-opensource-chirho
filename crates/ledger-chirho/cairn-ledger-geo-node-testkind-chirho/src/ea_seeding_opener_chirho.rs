// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The ONE place the credits-demo SEEDING road's injected opener names the E-A compensation-provider
//! door — the second sanctioned door reference in this crate, beside the winner-side E-B one.
//!
//! WHY THIS FILE EXISTS AND WHY IT IS HERE. The seeding road
//! (`cairn_operator_smoke_chirho::credits_demo_smoke_chirho::run_credits_demo_geo_seed_chirho`) must
//! be able to prepare a TEST-KIND root for a hosted drill, and its production resident door carries
//! the test-kind fence, so a marked config can never open there. The road therefore takes an
//! INJECTED opener and names no door itself — deliberately, because that crate reaches
//! `cairn-cli-chirho` by three link paths and a door named there would make the SHIPPING CLI capable
//! of autonomously completing a compensation. The widening lives here instead, in the crate no
//! production build links.
//!
//! WHICH DOOR, AND WHY NOT THE OTHER ONE. This opener reaches E-A
//! (`open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho`) rather than the
//! winner-side E-B door its sibling module uses, because the two differ in ELECTION posture and the
//! seeding road's posture is the single-voter one: the road it replaces opens
//! `open_resident_effect_journal_handle_chirho`, which is E-A's provider-less twin
//! (`ReopenOwnedSingleNodeChirho`). E-B exists for a winner composed on an already-running cluster
//! elector that carries an accepted handoff marker; seeding a fresh root has no such elector and no
//! handoff. Handing E-B a fresh self-election would be a different authority, not a spelling choice.
//!
//! The provider only REPORTS a settlement. No code on this path moves real money.

use crate::reporting_provider_chirho::TestkindSettlementReportingProviderChirho;
use anyhow::Result;
use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_ledger_host_chirho::{
    open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho,
    ResidentEffectJournalHandleChirho,
};
use cairn_operator_smoke_chirho::credits_demo_smoke_chirho::{
    run_credits_demo_geo_seed_chirho, CreditsDemoGeoSeedReportChirho, CreditsDemoSmokeInputsChirho,
};
use std::path::Path;

/// Open the seeding road's post-regenesis resident authority through the E-A compensation-provider
/// door, with a fresh synthetic reporting-only provider.
///
/// Signature note, and it is the load-bearing part: this matches
/// `CreditsDemoResidentOpenerChirho` exactly — three borrowed inputs, a
/// `ResidentEffectJournalHandleChirho` out — so the seeding road can invoke it while naming neither
/// this function nor the door it reaches. The provider is constructed HERE, which is why the
/// provider TYPE never appears in the seeding road's signature either.
///
/// This door carries NO test-kind fence, by design: the fence lives on the two provider-less
/// production doors precisely so a drill authored in test-kind mode can open here. A config that
/// reaches this function is still fully validated and custody-verified inside the door.
pub fn testkind_seeding_resident_opener_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
) -> Result<ResidentEffectJournalHandleChirho> {
    open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho(
        selected_root_chirho,
        config_path_chirho,
        config_chirho,
        None,
        Box::new(TestkindSettlementReportingProviderChirho::new_chirho()),
    )
}

/// Seed a TEST-KIND geo drill root: the shipping seeding road, with this crate's opener injected.
///
/// This is the whole consumer side of the E1-e-2 seam. Everything the road does — plan digest
/// binding, custody, freshness, H3 regenesis, the app authoring/review rail, the price book — is the
/// SAME production code the CLI runs; the single difference is which resident authority the road
/// opens after regenesis, and therefore whether a compensation can be completed on the seeded root.
pub fn run_testkind_credits_demo_geo_seed_chirho(
    inputs_chirho: &CreditsDemoSmokeInputsChirho<'_>,
) -> Result<CreditsDemoGeoSeedReportChirho> {
    run_credits_demo_geo_seed_chirho(
        inputs_chirho,
        Some(&testkind_seeding_resident_opener_chirho),
    )
}
