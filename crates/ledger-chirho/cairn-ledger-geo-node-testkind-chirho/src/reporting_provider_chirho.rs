// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The test-kind synthetic GD7 compensation provider: it REPORTS a settlement and performs nothing.

use cairn_ledger_host_chirho::{
    Gd7CompensationProviderAdapterChirho, Gd7CompensationProviderObservationChirho,
    Gd7CompensationProviderRefusalChirho,
};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Bounded, non-identifying labels for a compensation ACTION (a settlement report), never content —
/// the hosted-buildable analog of the regenesis test provider's `ROUTE_A_*` constants.
pub const TESTKIND_PROVIDER_EFFECT_ID_CHIRHO: &str = "gd7-testkind-provider-effect-id-chirho";
pub const TESTKIND_OBSERVATION_REF_CHIRHO: &str = "gd7-testkind-settlement-observation-ref-chirho";

/// Shared test observation log carried across the provider's actor-thread move.
pub type TestkindProviderCallLogChirho = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// A synthetic reporting-only GD7 compensation provider. It records that a settlement is CLAIMED
/// against a persisted, idempotency-keyed intent and MOVES NO MONEY: cairn records the claim and
/// never verifies the external side. A provider that moves real money is a separate,
/// operator-configured, hard-gated decision that no code in this crate takes.
///
/// The observation counters live behind `Arc` because the opener MOVES the provider into the actor
/// thread; without shared handles a proof arm could inject the provider or observe it, never both —
/// and an unobserved provider would make "executed exactly once" an unmeasured claim.
pub struct TestkindSettlementReportingProviderChirho {
    executions_chirho: Arc<AtomicU8>,
    keyed_calls_chirho: TestkindProviderCallLogChirho,
}

impl TestkindSettlementReportingProviderChirho {
    /// A fresh provider with private counters — the binary's shape, where nothing observes it.
    pub fn new_chirho() -> Self {
        Self {
            executions_chirho: Arc::new(AtomicU8::new(0)),
            keyed_calls_chirho: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// A provider that shares its observation counters, so a proof arm can prove "executed exactly
    /// once" after the opener has moved the provider into the actor thread.
    pub fn with_observers_chirho(
        executions_chirho: Arc<AtomicU8>,
        keyed_calls_chirho: TestkindProviderCallLogChirho,
    ) -> Self {
        Self {
            executions_chirho,
            keyed_calls_chirho,
        }
    }
}

impl Default for TestkindSettlementReportingProviderChirho {
    fn default() -> Self {
        Self::new_chirho()
    }
}

impl Gd7CompensationProviderAdapterChirho for TestkindSettlementReportingProviderChirho {
    fn dedup_retention_duration_chirho(&self) -> Duration {
        Duration::from_secs(3600)
    }

    fn execute_gd7_compensation_provider_chirho(
        &self,
        provider_idempotency_key_chirho: &str,
        bounded_payload_chirho: &[u8],
    ) -> Result<Gd7CompensationProviderObservationChirho, Gd7CompensationProviderRefusalChirho>
    {
        if provider_idempotency_key_chirho.is_empty() {
            return Err(Gd7CompensationProviderRefusalChirho::InvalidProviderKeyChirho);
        }
        self.executions_chirho.fetch_add(1, Ordering::SeqCst);
        self.keyed_calls_chirho
            .lock()
            .expect("the provider call log is never poisoned")
            .push((
                provider_idempotency_key_chirho.to_owned(),
                bounded_payload_chirho.to_vec(),
            ));
        Ok(Gd7CompensationProviderObservationChirho::ObservedChirho {
            observation_ref_chirho: TESTKIND_OBSERVATION_REF_CHIRHO.to_owned(),
            provider_effect_id_chirho: TESTKIND_PROVIDER_EFFECT_ID_CHIRHO.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn testkind_provider_reports_settlement_and_performs_nothing_chirho() {
        let executions_chirho = Arc::new(AtomicU8::new(0));
        let keyed_calls_chirho = Arc::new(Mutex::new(Vec::new()));
        let provider_chirho = TestkindSettlementReportingProviderChirho::with_observers_chirho(
            Arc::clone(&executions_chirho),
            Arc::clone(&keyed_calls_chirho),
        );
        assert_eq!(
            provider_chirho.dedup_retention_duration_chirho(),
            Duration::from_secs(3600),
            "a reporting-only provider still retains its idempotency keys"
        );

        let observation_chirho = provider_chirho
            .execute_gd7_compensation_provider_chirho("gd7-testkind-key-chirho", b"bounded-payload")
            .expect("a reporting-only provider observes a settlement against a non-empty key");
        match observation_chirho {
            Gd7CompensationProviderObservationChirho::ObservedChirho {
                observation_ref_chirho,
                provider_effect_id_chirho,
            } => {
                assert_eq!(observation_ref_chirho, TESTKIND_OBSERVATION_REF_CHIRHO);
                assert_eq!(
                    provider_effect_id_chirho,
                    TESTKIND_PROVIDER_EFFECT_ID_CHIRHO
                );
            }
            _other_chirho => {
                panic!("a reporting-only provider must OBSERVE a settlement, never report in-doubt")
            }
        }

        // Executed exactly once, against the exact keyed intent it was handed — and it moved no
        // money: the only durable trace is the recorded (key, payload) pair.
        assert_eq!(executions_chirho.load(Ordering::SeqCst), 1);
        let recorded_chirho = keyed_calls_chirho
            .lock()
            .expect("call log is never poisoned");
        assert_eq!(recorded_chirho.len(), 1);
        assert_eq!(recorded_chirho[0].0, "gd7-testkind-key-chirho");
        assert_eq!(recorded_chirho[0].1, b"bounded-payload".to_vec());
    }

    #[test]
    fn testkind_provider_refuses_an_empty_idempotency_key_chirho() {
        let provider_chirho = TestkindSettlementReportingProviderChirho::new_chirho();
        let refusal_chirho = provider_chirho
            .execute_gd7_compensation_provider_chirho("", b"bounded-payload")
            .expect_err("the composition must never dispatch an empty provider idempotency key");
        assert!(matches!(
            refusal_chirho,
            Gd7CompensationProviderRefusalChirho::InvalidProviderKeyChirho
        ));
    }
}
