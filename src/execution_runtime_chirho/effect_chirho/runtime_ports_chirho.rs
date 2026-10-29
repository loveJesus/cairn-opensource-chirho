// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Explicit effect-runtime ports threaded through one DAG execution.
//! Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md` 9.4.

use super::llm_served_chirho::LlmServedRuntimePortChirho;
use super::postgres_reversible_chirho::PostgresReversibleRuntimePortChirho;
use super::projection_read_chirho::PublishedProjectionReadPortChirho;
use crate::privacy_chirho::PrivateBlobAttributionChirho;

/// Transient composition authority for one DAG execution.
///
/// The bundle owns no defaults and performs no ambient lookup. Legacy entrypoints construct it
/// with the Descriptor-D and served-LLM ports absent, preserving the typed uncomposed refusal.
pub struct DagEffectRuntimePortsChirho<'runtime_chirho> {
    pub projection_read_chirho: Option<&'runtime_chirho dyn PublishedProjectionReadPortChirho>,
    pub postgres_reversible_chirho:
        Option<&'runtime_chirho mut dyn PostgresReversibleRuntimePortChirho>,
    pub llm_served_chirho: Option<&'runtime_chirho mut dyn LlmServedRuntimePortChirho>,
    /// Whose container a run with NO request context puts its private values in: serve declares the app
    /// owner for an anonymous app request, an operator run declares its reason. A run with a request
    /// context ignores it. `None` refuses any private store such a run attempts; nothing defaults.
    pub private_attribution_chirho: Option<&'runtime_chirho PrivateBlobAttributionChirho>,
}

impl DagEffectRuntimePortsChirho<'_> {
    pub fn uncomposed_chirho() -> Self {
        Self {
            projection_read_chirho: None,
            postgres_reversible_chirho: None,
            llm_served_chirho: None,
            private_attribution_chirho: None,
        }
    }

    /// Reborrow the same injected authorities for one node or one resumed run. The shorter
    /// lifetime prevents a loop iteration from retaining the mutable provider into the next one.
    pub fn reborrow_chirho(&mut self) -> DagEffectRuntimePortsChirho<'_> {
        let postgres_reversible_chirho =
            self.postgres_reversible_chirho
                .as_mut()
                .map(|postgres_reversible_chirho| {
                    &mut **postgres_reversible_chirho
                        as &mut dyn PostgresReversibleRuntimePortChirho
                });
        let llm_served_chirho = self.llm_served_chirho.as_mut().map(|llm_served_chirho| {
            &mut **llm_served_chirho as &mut dyn LlmServedRuntimePortChirho
        });
        DagEffectRuntimePortsChirho {
            projection_read_chirho: self.projection_read_chirho,
            postgres_reversible_chirho,
            llm_served_chirho,
            private_attribution_chirho: self.private_attribution_chirho,
        }
    }
}
