// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Per-run effect storage and injected runtime authority options.

use super::llm_served_chirho::LlmServedRuntimePortChirho;
use super::postgres_reversible_chirho::PostgresReversibleRuntimePortChirho;
use crate::blessed_chirho::EffectAdmissionChirho;
use crate::dag_private_value_chirho::{
    PrivateDagValueContextChirho, RunAttributionSourceChirho, ValueStoragePolicyChirho,
};
use crate::model_chirho::{HashChirho, RequestContextChirho};

#[derive(Default)]
pub struct EffectValueStorageChirho {
    pub request_hash_chirho: Option<HashChirho>,
    pub response_storage_chirho: Option<ValueStoragePolicyChirho>,
    pub response_context_chirho: PrivateDagValueContextChirho,
}

/// How an effect's response is stored, and whose container a private response joins.
pub(super) struct EffectResponseStorageChirho<'context_chirho> {
    pub(super) storage_chirho: EffectValueStorageChirho,
    pub(super) attribution_source_chirho: RunAttributionSourceChirho<'context_chirho>,
}

pub(super) struct EffectRunOptionsChirho<'context_chirho, 'admission_chirho, 'runtime_chirho> {
    pub(super) storage_chirho: EffectValueStorageChirho,
    pub(super) request_context_chirho: Option<&'context_chirho RequestContextChirho>,
    /// Whose container this effect's private values and seals join.
    pub(super) attribution_source_chirho: RunAttributionSourceChirho<'context_chirho>,
    pub(super) admission_chirho: &'admission_chirho EffectAdmissionChirho,
    pub(super) postgres_reversible_chirho:
        Option<&'runtime_chirho mut dyn PostgresReversibleRuntimePortChirho>,
    pub(super) llm_served_chirho: Option<&'runtime_chirho mut dyn LlmServedRuntimePortChirho>,
}

pub(crate) struct AdmittedEffectRunOptionsChirho<
    'context_chirho,
    'admission_chirho,
    'runtime_chirho,
> {
    pub(crate) storage_chirho: EffectValueStorageChirho,
    pub(crate) request_context_chirho: Option<&'context_chirho RequestContextChirho>,
    pub(crate) attribution_source_chirho: RunAttributionSourceChirho<'context_chirho>,
    pub(crate) admission_chirho: &'admission_chirho EffectAdmissionChirho,
    pub(crate) postgres_reversible_chirho:
        Option<&'runtime_chirho mut dyn PostgresReversibleRuntimePortChirho>,
    pub(crate) llm_served_chirho: Option<&'runtime_chirho mut dyn LlmServedRuntimePortChirho>,
}
