// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Read-only storage adapter for transient elected app reads.

use super::{ResourceGateSelectionChirho, ServedRuntimeRootChirho};
use anyhow::{anyhow, Result};
use cairn_core_chirho::{
    cas_chirho::{read_verified_bounded_chirho, CasReadOutcomeChirho},
    model_chirho::{DagChirho, HashChirho, RefsChirho, RequestContextChirho},
    ports_chirho::{ContentReadChirho, StoreErrorChirho, StoreResultChirho},
};
use cairn_pure_executor_chirho::{run_pure_dag_chirho, PureDagOutcomeChirho};
use std::path::Path;

const PURE_READ_OBJECT_MAX_BYTES_CHIRHO: u64 = 8 * 1024 * 1024;
const PURE_READ_MAX_NODES_CHIRHO: usize = 256;

struct PureReadContentChirho<'a>(&'a Path);

impl ContentReadChirho for PureReadContentChirho<'_> {
    fn get_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>> {
        match read_verified_bounded_chirho(self.0, addr_chirho, PURE_READ_OBJECT_MAX_BYTES_CHIRHO) {
            CasReadOutcomeChirho::VerifiedChirho(bytes_chirho) => Ok(Some(bytes_chirho)),
            CasReadOutcomeChirho::AbsentChirho(_) => Ok(None),
            CasReadOutcomeChirho::UnreadableChirho(error_chirho) => Err(error_chirho.into()),
            CasReadOutcomeChirho::TamperedChirho { .. } => Err(StoreErrorChirho::invalid_chirho(
                "pure read content did not verify",
            )),
        }
    }
}

impl ServedRuntimeRootChirho {
    pub(in crate::serve_chirho) fn select_pure_app_route_chirho(
        &self,
        refs_chirho: &RefsChirho,
        app_chirho: &str,
        route_chirho: &str,
        context_chirho: Option<&RequestContextChirho>,
    ) -> Result<Option<ResourceGateSelectionChirho>> {
        super::super::resource_gate_chirho::select_app_route_dag_without_resource_usage_chirho(
            &self.root_chirho,
            refs_chirho,
            app_chirho,
            route_chirho,
            context_chirho,
        )
    }

    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/pure-app-read-chirho.md`.
    pub(in crate::serve_chirho) fn execute_pure_app_read_chirho(
        &self,
        dag_hash_chirho: &HashChirho,
        input_chirho: &[u8],
    ) -> Result<PureDagOutcomeChirho> {
        let store_chirho = PureReadContentChirho(&self.root_chirho);
        let bytes_chirho = store_chirho
            .get_chirho(dag_hash_chirho)?
            .ok_or_else(|| anyhow!("pure read DAG is absent"))?;
        let dag_chirho: DagChirho = serde_json::from_slice(&bytes_chirho)?;
        if dag_chirho.nodes_chirho.len() > PURE_READ_MAX_NODES_CHIRHO
            || dag_chirho.edges_chirho.len() > PURE_READ_MAX_NODES_CHIRHO
        {
            anyhow::bail!("pure read DAG exceeds its bounded chain size");
        }
        run_pure_dag_chirho(
            &store_chirho,
            &dag_chirho,
            input_chirho,
            cairn_write_relay_chirho::RELAY_RESPONSE_BODY_MAX_BYTES_CHIRHO,
        )
    }
}

#[cfg(test)]
#[path = "pure_read_chirho/tests_chirho.rs"]
mod tests_chirho;
