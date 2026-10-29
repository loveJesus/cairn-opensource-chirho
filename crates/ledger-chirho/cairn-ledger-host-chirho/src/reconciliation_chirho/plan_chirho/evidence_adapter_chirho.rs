// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Production root adapter for bounded GD7 intent and terminal evidence.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use super::contract_chirho::Gd7EffectEvidenceReaderPortChirho;
use anyhow::Result;
use cairn_effect_commit_ledger_chirho::public_evidence_chirho::{
    PublicEffectEvidenceKindChirho, RootPublicEffectEvidenceStoreChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct RootGd7EffectEvidenceReaderChirho {
    store_chirho: RootPublicEffectEvidenceStoreChirho,
}

impl RootGd7EffectEvidenceReaderChirho {
    pub fn new_chirho(root_chirho: &Path) -> Self {
        Self {
            store_chirho: RootPublicEffectEvidenceStoreChirho::new_chirho(root_chirho),
        }
    }
}

impl Gd7EffectEvidenceReaderPortChirho for RootGd7EffectEvidenceReaderChirho {
    fn load_intent_line_bounded_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
        maximum_bytes_chirho: usize,
    ) -> Result<Option<Vec<u8>>> {
        self.store_chirho
            .load_bounded_chirho(
                PublicEffectEvidenceKindChirho::WarrantChirho,
                &intent_ref_chirho.0,
                maximum_bytes_chirho,
            )
            .map_err(anyhow::Error::new)
    }

    fn load_terminal_line_bounded_chirho(
        &self,
        outcome_ref_chirho: &DigestChirho,
        maximum_bytes_chirho: usize,
    ) -> Result<Option<Vec<u8>>> {
        self.store_chirho
            .load_bounded_chirho(
                PublicEffectEvidenceKindChirho::TerminalChirho,
                &outcome_ref_chirho.0,
                maximum_bytes_chirho,
            )
            .map_err(anyhow::Error::new)
    }
}
