// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The ONE place any crate outside `cairn-ledger-host-chirho` names the DEV-ONLY test-kind resident
//! door `open_resident_effect_journal_handle_testkind_chirho` — the normal-settlement opener for a
//! synthetic test-kind root.
//!
//! WHY THIS FILE EXISTS AND WHY IT IS HERE. A dev-context proof (a2) must drive one served-LLM draft
//! to completion on a1's DEV bootstrap root, which is TEST-KIND by design. The production single-node
//! resident door refuses a test-kind config, so opening a1's root needs the inverse-fenced twin
//! `open_resident_effect_journal_handle_testkind_chirho`. That door lives in the host crate; this
//! opener is its SOLE lawful non-definition caller, and it lives here — in the dev-only
//! `cairn-ledger-geo-node-testkind-chirho` crate that no production build links
//! (`testkind_geo_node_stays_a_dev_only_edge_chirho`), confined by the source guard
//! `open_resident_effect_journal_handle_testkind_door_has_no_shipping_binary_caller_chirho`.
//!
//! WHY NO PROVIDER, unlike the E-A/E-B openers. Those reach the GD7 COMPENSATION-provider door and
//! must hand it a completing provider. THIS opener reaches the normal-settlement door, which carries
//! ZERO compensation capability (the refusing default): a plain within-kind settlement on a fresh
//! single-node root has no GD7 obligation to compensate, so there is no provider to construct. The
//! opener is therefore the door plus its fixed `None` conservation provider — nothing more.
//!
//! The config that reaches this opener is still fully validated and custody-verified inside the door,
//! exactly as the production door validates; the only thing that differs from production is the fence
//! DIRECTION (this one REQUIRES the test-kind marker).

use anyhow::Result;
use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_ledger_host_chirho::{
    open_resident_effect_journal_handle_testkind_chirho, ResidentEffectJournalHandleChirho,
};
use std::path::Path;

/// Open a SYNTHETIC test-kind root's resident authority through the dev-only normal-settlement door.
///
/// Signature note: three borrowed inputs, a `ResidentEffectJournalHandleChirho` out — the same shape
/// the production single-node door presents, minus its conservation-provider option (fixed to `None`
/// here, since a plain dev settlement carries no GD7 conservation obligation). The returned handle is
/// the exact fenced actor handle the production door yields; nothing about the elected-writer fence,
/// the lease, or the mailbox serialization is relaxed.
pub fn testkind_normal_settlement_resident_opener_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
) -> Result<ResidentEffectJournalHandleChirho> {
    open_resident_effect_journal_handle_testkind_chirho(
        selected_root_chirho,
        config_path_chirho,
        config_chirho,
        None,
    )
}
