// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Typed GD7 composition seams owned by the resident actor command loop.

use crate::reconciliation_chirho::{
    mark_gd7_obligation_held_manual_chirho, prepare_gd7_provider_resume_chirho,
    record_gd7_provider_intent_chirho, record_gd7_provider_observation_chirho,
    Gd7ObligationProcessingRefusalChirho, Gd7ObligationProcessingStateChirho,
};
use cairn_effect_commit_chirho::compensation_chirho::VerifiedEffectCompensationChirho;
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
#[cfg(test)]
use std::cell::Cell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Gd7CurrentWinnerCompensationAuthorityChirho {
    published_raft_term_chirho: u64,
}

impl Gd7CurrentWinnerCompensationAuthorityChirho {
    pub(crate) fn published_raft_term_chirho(&self) -> u64 {
        self.published_raft_term_chirho
    }
}

/// `pub` is the capstone's layer-2 seam: a completing provider lives in the custody-verified world
/// DOWNSTREAM of this crate (`cairn-ledger-regenesis-chirho`) and must construct this observation
/// to report a settlement. The `dead_code` allow that stood here — "observed and in-doubt outcomes
/// are supplied by the later gated provider adapter" — named exactly this moment and dies by
/// consumption, the twice-observed census pattern. Widening the TYPE grants no authority: an
/// observation only takes effect through `compose_gd7_provider_result_chirho`, which records it
/// against a persisted, idempotency-keyed intent — recorded as the provider's CLAIM, never as a
/// cairn-verified fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gd7CompensationProviderObservationChirho {
    ObservedChirho {
        observation_ref_chirho: String,
        provider_effect_id_chirho: String,
    },
    InDoubtChirho {
        evidence_chirho: String,
    },
}

#[allow(
    dead_code,
    reason = "unavailable is returned by mailbox loss and the production refusal adapter does not lose its mailbox"
)]
/// `pub` transitively: it is a payload of the now-public `Gd7CompensationCompletionRefusalChirho`,
/// which is the error type of the public `complete_gd7_compensation_chirho` wire method. Leaving it
/// crate-private would keep a `private_interfaces` warning standing in a zero-warning gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gd7CompensationProviderRefusalChirho {
    ProviderNotConfiguredChirho,
    InvalidProviderKeyChirho,
    InvalidPayloadChirho,
    TenantMigrationSourceFenceActiveChirho,
    UnavailableChirho { detail_chirho: String },
}

/// Exact reason one bounded composition step could not advance the obligation.
///
/// `pub` for the same reason as its neighbour `Gd7CompensationCompletionRefusalChirho`: it is the
/// error type of the now-`pub` `ResidentEffectJournalHandleChirho::compose_gd7_compensation_chirho`
/// wire method, and a public method whose error type is crate-private is a `private_interfaces`
/// warning — the caller could receive the value but not name it, which in practice means it could
/// not assert on the variant, and asserting the exact variant is the whole point on this path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gd7CompensationCompositionRefusalChirho {
    TenantMigrationSourceFenceActiveChirho,
    ProviderChirho(Gd7CompensationProviderRefusalChirho),
    ProcessingChirho(Gd7ObligationProcessingRefusalChirho),
    #[cfg(test)]
    CrashInjectedChirho,
}

pub(crate) struct RefusingGd7CompensationProviderChirho;

impl Gd7CompensationProviderAdapterChirho for RefusingGd7CompensationProviderChirho {
    fn dedup_retention_duration_chirho(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }

    fn execute_gd7_compensation_provider_chirho(
        &self,
        _provider_idempotency_key_chirho: &str,
        _bounded_payload_chirho: &[u8],
    ) -> Result<Gd7CompensationProviderObservationChirho, Gd7CompensationProviderRefusalChirho>
    {
        Err(Gd7CompensationProviderRefusalChirho::ProviderNotConfiguredChirho)
    }
}

/// The provider PORT for one bounded compensation step — the only seam through which the outside
/// world reports that a compensation settled.
///
/// `pub` for the same crate-boundary reason the wire methods carry: the custody-verified actor
/// world in `cairn-ledger-regenesis-chirho` is DOWNSTREAM of this crate, so a completing provider
/// (the capstone's layer 2 — it REPORTS settlement and moves no money) could not even name the
/// trait it must implement. Visibility carries no authority: a provider only runs when a
/// composition hands it to the one opener that accepts one, every other opener wires the refusing
/// default, and everything a provider returns is recorded against a persisted idempotency-keyed
/// intent as the provider's claim — cairn never verifies the external side. A provider that moves
/// real money is a separate, operator-configured, hard-gated decision no code in this crate takes.
pub trait Gd7CompensationProviderAdapterChirho {
    /// The adapter must retain idempotency keys for at least this duration.
    fn dedup_retention_duration_chirho(&self) -> std::time::Duration;

    fn execute_gd7_compensation_provider_chirho(
        &self,
        provider_idempotency_key_chirho: &str,
        bounded_payload_chirho: &[u8],
    ) -> Result<Gd7CompensationProviderObservationChirho, Gd7CompensationProviderRefusalChirho>;
}

pub(crate) fn derive_gd7_compensation_provider_idempotency_key_chirho(
    canonical_obligation_digest_chirho: &str,
    action_idempotency_key_chirho: &str,
) -> Result<String, Gd7CompensationProviderRefusalChirho> {
    if canonical_obligation_digest_chirho.is_empty() || action_idempotency_key_chirho.is_empty() {
        return Err(Gd7CompensationProviderRefusalChirho::InvalidProviderKeyChirho);
    }
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(b"gd7-compensation-provider-idempotency-v1-chirho\0");
    hasher_chirho.update(
        canonical_obligation_digest_chirho
            .len()
            .to_string()
            .as_bytes(),
    );
    hasher_chirho.update(b":");
    hasher_chirho.update(canonical_obligation_digest_chirho.as_bytes());
    hasher_chirho.update(action_idempotency_key_chirho.len().to_string().as_bytes());
    hasher_chirho.update(b":");
    hasher_chirho.update(action_idempotency_key_chirho.as_bytes());
    Ok(format!(
        "gd7-compensation-provider-chirho:{}",
        hasher_chirho.finalize().to_hex()
    ))
}

pub(crate) fn execute_gd7_compensation_provider_chirho(
    adapter_chirho: &dyn Gd7CompensationProviderAdapterChirho,
    provider_idempotency_key_chirho: &str,
    bounded_payload_chirho: &[u8],
) -> Result<Gd7CompensationProviderObservationChirho, Gd7CompensationProviderRefusalChirho> {
    if provider_idempotency_key_chirho.is_empty() {
        return Err(Gd7CompensationProviderRefusalChirho::InvalidProviderKeyChirho);
    }
    if bounded_payload_chirho.len() > 64 * 1024 {
        return Err(Gd7CompensationProviderRefusalChirho::InvalidPayloadChirho);
    }
    adapter_chirho.execute_gd7_compensation_provider_chirho(
        provider_idempotency_key_chirho,
        bounded_payload_chirho,
    )
}

pub(crate) fn compose_gd7_provider_result_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    state_chirho: &Gd7ObligationProcessingStateChirho,
    adapter_chirho: &dyn Gd7CompensationProviderAdapterChirho,
    bounded_payload_chirho: &[u8],
) -> Result<Gd7ObligationProcessingStateChirho, Gd7CompensationCompositionRefusalChirho> {
    let provider_key_chirho = derive_gd7_compensation_provider_idempotency_key_chirho(
        state_chirho.canonical_obligation_digest_chirho(),
        state_chirho.action_idempotency_key_chirho(),
    )
    .map_err(Gd7CompensationCompositionRefusalChirho::ProviderChirho)?;
    let payload_digest_chirho = blake3::hash(bounded_payload_chirho).to_hex().to_string();
    let intent_state_chirho = if state_chirho.provider_idempotency_key_chirho().is_some() {
        match prepare_gd7_provider_resume_chirho(
            storage_chirho,
            state_chirho,
            &payload_digest_chirho,
            adapter_chirho.dedup_retention_duration_chirho().as_secs(),
            3,
        ) {
            Ok(next_state_chirho) => next_state_chirho,
            Err(
                refusal_chirho @ (Gd7ObligationProcessingRefusalChirho::ResumeWindowExpiredChirho
                | Gd7ObligationProcessingRefusalChirho::ResumeAttemptsExceededChirho),
            ) => {
                mark_gd7_obligation_held_manual_chirho(storage_chirho, state_chirho)
                    .map_err(Gd7CompensationCompositionRefusalChirho::ProcessingChirho)?;
                return Err(Gd7CompensationCompositionRefusalChirho::ProcessingChirho(
                    refusal_chirho,
                ));
            }
            Err(refusal_chirho) => {
                return Err(Gd7CompensationCompositionRefusalChirho::ProcessingChirho(
                    refusal_chirho,
                ));
            }
        }
    } else {
        record_gd7_provider_intent_chirho(
            storage_chirho,
            state_chirho,
            &provider_key_chirho,
            &payload_digest_chirho,
        )
        .map_err(Gd7CompensationCompositionRefusalChirho::ProcessingChirho)?
    };
    failpoint_gd7_provider_chirho("after-intent-before-dispatch-chirho")?;
    let observation_chirho = execute_gd7_compensation_provider_chirho(
        adapter_chirho,
        &provider_key_chirho,
        bounded_payload_chirho,
    )
    .map_err(Gd7CompensationCompositionRefusalChirho::ProviderChirho)?;
    failpoint_gd7_provider_chirho("after-provider-before-observation-chirho")?;
    match observation_chirho {
        Gd7CompensationProviderObservationChirho::ObservedChirho {
            observation_ref_chirho,
            provider_effect_id_chirho,
        } => record_gd7_provider_observation_chirho(
            storage_chirho,
            &intent_state_chirho,
            &observation_ref_chirho,
            &provider_effect_id_chirho,
        )
        .map_err(Gd7CompensationCompositionRefusalChirho::ProcessingChirho),
        Gd7CompensationProviderObservationChirho::InDoubtChirho { .. } => {
            mark_gd7_obligation_held_manual_chirho(storage_chirho, state_chirho)
                .map_err(Gd7CompensationCompositionRefusalChirho::ProcessingChirho)
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static GD7_PROVIDER_FAILPOINT_CHIRHO: Cell<Option<&'static str>> = const { Cell::new(None) };
}

#[cfg(test)]
fn arm_gd7_provider_failpoint_chirho(name_chirho: &'static str) {
    GD7_PROVIDER_FAILPOINT_CHIRHO.with(|failpoint_chirho| failpoint_chirho.set(Some(name_chirho)));
}

fn failpoint_gd7_provider_chirho(
    _expected_name_chirho: &'static str,
) -> Result<(), Gd7CompensationCompositionRefusalChirho> {
    #[cfg(test)]
    if GD7_PROVIDER_FAILPOINT_CHIRHO.with(|failpoint_chirho| {
        let armed_chirho = failpoint_chirho.get();
        if armed_chirho == Some(_expected_name_chirho) {
            failpoint_chirho.set(None);
            true
        } else {
            false
        }
    }) {
        return Err(Gd7CompensationCompositionRefusalChirho::CrashInjectedChirho);
    }
    Ok(())
}

pub(crate) fn derive_current_gd7_winner_compensation_authority_chirho(
    published_raft_term_chirho: u64,
    _authorization_chirho: &VerifiedEffectCompensationChirho,
) -> Result<Gd7CurrentWinnerCompensationAuthorityChirho, &'static str> {
    if published_raft_term_chirho == 0 {
        return Err("current winner term must be nonzero");
    }
    Ok(Gd7CurrentWinnerCompensationAuthorityChirho {
        published_raft_term_chirho,
    })
}

#[cfg(test)]
mod composition_tests_chirho {
    use super::*;
    use crate::reconciliation_chirho::create_or_load_gd7_obligation_processing_state_chirho;
    use crate::FsLedgerStorageChirho;
    use std::cell::{Cell, RefCell};
    use std::fs;

    struct ObservingProviderChirho;

    struct KeyHonoringProviderChirho {
        calls_chirho: Cell<u8>,
        keys_chirho: RefCell<Vec<String>>,
    }

    impl KeyHonoringProviderChirho {
        fn new_chirho() -> Self {
            Self {
                calls_chirho: Cell::new(0),
                keys_chirho: RefCell::new(Vec::new()),
            }
        }
    }

    impl Gd7CompensationProviderAdapterChirho for KeyHonoringProviderChirho {
        fn dedup_retention_duration_chirho(&self) -> std::time::Duration {
            std::time::Duration::from_secs(3600)
        }

        fn execute_gd7_compensation_provider_chirho(
            &self,
            provider_idempotency_key_chirho: &str,
            bounded_payload_chirho: &[u8],
        ) -> Result<Gd7CompensationProviderObservationChirho, Gd7CompensationProviderRefusalChirho>
        {
            self.calls_chirho
                .set(self.calls_chirho.get().saturating_add(1));
            assert!(!provider_idempotency_key_chirho.is_empty());
            self.keys_chirho.borrow_mut().push(format!(
                "{provider_idempotency_key_chirho}:{}",
                blake3::hash(bounded_payload_chirho).to_hex()
            ));
            Ok(Gd7CompensationProviderObservationChirho::ObservedChirho {
                observation_ref_chirho: "replayed-observation-chirho".to_owned(),
                provider_effect_id_chirho: "same-provider-effect-chirho".to_owned(),
            })
        }
    }

    impl Gd7CompensationProviderAdapterChirho for ObservingProviderChirho {
        fn dedup_retention_duration_chirho(&self) -> std::time::Duration {
            std::time::Duration::from_secs(3600)
        }

        fn execute_gd7_compensation_provider_chirho(
            &self,
            _provider_idempotency_key_chirho: &str,
            _bounded_payload_chirho: &[u8],
        ) -> Result<Gd7CompensationProviderObservationChirho, Gd7CompensationProviderRefusalChirho>
        {
            Ok(Gd7CompensationProviderObservationChirho::ObservedChirho {
                observation_ref_chirho: "observation-composition-test-chirho".to_owned(),
                provider_effect_id_chirho: "effect-composition-test-chirho".to_owned(),
            })
        }
    }

    #[test]
    fn observed_provider_result_persists_through_r2r3_chirho() {
        let directory_chirho = std::env::temp_dir().join(format!(
            "cairn-gd7-composition-{}-chirho",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory_chirho);
        fs::create_dir_all(&directory_chirho).expect("composition test storage");
        let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&directory_chirho)
            .expect("open composition test storage");
        let state_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "receipt-composition-test-chirho",
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "inverse-composition-test-chirho",
            "action-composition-test-chirho",
        )
        .expect("create composition state");
        let next_state_chirho = compose_gd7_provider_result_chirho(
            &storage_chirho,
            &state_chirho,
            &ObservingProviderChirho,
            b"bounded-payload-chirho",
        )
        .expect("observed provider result persists");
        assert_eq!(
            next_state_chirho.provider_observation_ref_chirho(),
            Some("observation-composition-test-chirho")
        );
        assert!(next_state_chirho
            .provider_idempotency_key_chirho()
            .is_some());
    }

    #[test]
    fn provider_window_failpoints_apply_at_both_boundaries_chirho() {
        let directory_chirho = std::env::temp_dir().join(format!(
            "cairn-gd7-provider-failpoints-{}-chirho",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory_chirho);
        fs::create_dir_all(&directory_chirho).expect("provider failpoint storage");
        let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&directory_chirho)
            .expect("open provider failpoint storage");
        let state_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "receipt-provider-failpoint-chirho",
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "inverse-provider-failpoint-chirho",
            "action-provider-failpoint-chirho",
        )
        .expect("create provider failpoint state");

        arm_gd7_provider_failpoint_chirho("after-intent-before-dispatch-chirho");
        assert_eq!(
            compose_gd7_provider_result_chirho(
                &storage_chirho,
                &state_chirho,
                &ObservingProviderChirho,
                b"provider-failpoint-payload-chirho",
            ),
            Err(Gd7CompensationCompositionRefusalChirho::CrashInjectedChirho)
        );
        let intent_state_chirho =
            crate::reconciliation_chirho::load_gd7_obligation_processing_state_chirho(
                &storage_chirho,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("reload intent after dispatch failpoint");
        assert_eq!(
            intent_state_chirho.terminal_progress_chirho(),
            crate::reconciliation_chirho::Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho
        );

        arm_gd7_provider_failpoint_chirho("after-provider-before-observation-chirho");
        assert_eq!(
            compose_gd7_provider_result_chirho(
                &storage_chirho,
                &intent_state_chirho,
                &ObservingProviderChirho,
                b"provider-failpoint-payload-chirho",
            ),
            Err(Gd7CompensationCompositionRefusalChirho::CrashInjectedChirho)
        );
        let still_intent_chirho =
            crate::reconciliation_chirho::load_gd7_obligation_processing_state_chirho(
                &storage_chirho,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("reload intent after observation failpoint");
        assert_eq!(
            still_intent_chirho.terminal_progress_chirho(),
            crate::reconciliation_chirho::Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho
        );
    }

    #[test]
    fn refusing_provider_returns_named_refusal_without_state_advance_chirho() {
        let directory_chirho = std::env::temp_dir().join(format!(
            "cairn-gd7-provider-refusal-{}-chirho",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory_chirho);
        fs::create_dir_all(&directory_chirho).expect("provider refusal storage");
        let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&directory_chirho)
            .expect("open provider refusal storage");
        let state_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "receipt-provider-refusal-chirho",
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "inverse-provider-refusal-chirho",
            "action-provider-refusal-chirho",
        )
        .expect("create provider refusal state");
        assert_eq!(
            compose_gd7_provider_result_chirho(
                &storage_chirho,
                &state_chirho,
                &RefusingGd7CompensationProviderChirho,
                b"provider-refusal-payload-chirho",
            ),
            Err(Gd7CompensationCompositionRefusalChirho::ProviderChirho(
                Gd7CompensationProviderRefusalChirho::ProviderNotConfiguredChirho,
            ))
        );
        let reopened_chirho =
            crate::reconciliation_chirho::load_gd7_obligation_processing_state_chirho(
                &storage_chirho,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("reload provider refusal state");
        assert_eq!(
            reopened_chirho.terminal_progress_chirho(),
            crate::reconciliation_chirho::Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho
        );
        assert!(reopened_chirho.provider_observation_ref_chirho().is_none());
        fs::remove_dir_all(directory_chirho).expect("remove provider refusal storage");
    }

    #[test]
    fn expired_provider_resume_marks_held_manual_and_preserves_refusal_chirho() {
        let directory_chirho = std::env::temp_dir().join(format!(
            "cairn-gd7-provider-expired-resume-{}-chirho",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory_chirho);
        fs::create_dir_all(&directory_chirho).expect("expired resume storage");
        let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&directory_chirho)
            .expect("open expired resume storage");
        let state_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "receipt-expired-resume-chirho",
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "inverse-expired-resume-chirho",
            "action-expired-resume-chirho",
        )
        .expect("create expired resume state");
        assert_eq!(
            compose_gd7_provider_result_chirho(
                &storage_chirho,
                &state_chirho,
                &RefusingGd7CompensationProviderChirho,
                b"expired-resume-payload-chirho",
            ),
            Err(Gd7CompensationCompositionRefusalChirho::ProviderChirho(
                Gd7CompensationProviderRefusalChirho::ProviderNotConfiguredChirho,
            ))
        );
        let intent_state_chirho =
            crate::reconciliation_chirho::load_gd7_obligation_processing_state_chirho(
                &storage_chirho,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("reload expired resume intent");
        assert_eq!(
            compose_gd7_provider_result_chirho(
                &storage_chirho,
                &intent_state_chirho,
                &RefusingGd7CompensationProviderChirho,
                b"expired-resume-payload-chirho",
            ),
            Err(Gd7CompensationCompositionRefusalChirho::ProcessingChirho(
                Gd7ObligationProcessingRefusalChirho::ResumeWindowExpiredChirho,
            ))
        );
        assert_eq!(
            crate::reconciliation_chirho::load_gd7_obligation_processing_state_chirho(
                &storage_chirho,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("reload held expired resume")
            .terminal_progress_chirho(),
            crate::reconciliation_chirho::Gd7ObligationTerminalProgressChirho::HeldManualChirho
        );
        let display_records_chirho =
            crate::reconciliation_chirho::load_gd7_obligation_processing_for_display_chirho(
                &storage_chirho,
            )
            .expect("load expired resume for operator display");
        assert_eq!(display_records_chirho.len(), 1);
        assert_eq!(
            display_records_chirho[0]
                .state_chirho
                .as_ref()
                .expect("expired resume display state")
                .terminal_progress_chirho(),
            crate::reconciliation_chirho::Gd7ObligationTerminalProgressChirho::HeldManualChirho
        );
        fs::remove_dir_all(directory_chirho).expect("remove expired resume storage");
    }

    #[test]
    fn exceeded_provider_resume_marks_held_manual_and_preserves_refusal_chirho() {
        let directory_chirho = std::env::temp_dir().join(format!(
            "cairn-gd7-provider-attempt-limit-{}-chirho",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory_chirho);
        fs::create_dir_all(&directory_chirho).expect("attempt limit storage");
        let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&directory_chirho)
            .expect("open attempt limit storage");
        let state_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "receipt-attempt-limit-chirho",
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "inverse-attempt-limit-chirho",
            "action-attempt-limit-chirho",
        )
        .expect("create attempt limit state");
        let provider_chirho = KeyHonoringProviderChirho::new_chirho();
        let payload_chirho = b"attempt-limit-payload-chirho";
        arm_gd7_provider_failpoint_chirho("after-intent-before-dispatch-chirho");
        assert_eq!(
            compose_gd7_provider_result_chirho(
                &storage_chirho,
                &state_chirho,
                &provider_chirho,
                payload_chirho,
            )
            .expect_err("initial provider call must stop at the injected boundary"),
            Gd7CompensationCompositionRefusalChirho::CrashInjectedChirho
        );
        let mut intent_state_chirho =
            crate::reconciliation_chirho::load_gd7_obligation_processing_state_chirho(
                &storage_chirho,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("reload attempt-limit intent");
        for _attempt_chirho in 0..3 {
            arm_gd7_provider_failpoint_chirho("after-provider-before-observation-chirho");
            assert_eq!(
                compose_gd7_provider_result_chirho(
                    &storage_chirho,
                    &intent_state_chirho,
                    &provider_chirho,
                    payload_chirho,
                )
                .expect_err("provider observation failpoint must leave intent resumable"),
                Gd7CompensationCompositionRefusalChirho::CrashInjectedChirho
            );
            intent_state_chirho =
                crate::reconciliation_chirho::load_gd7_obligation_processing_state_chirho(
                    &storage_chirho,
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .expect("reload bounded resume intent");
        }
        assert_eq!(
            compose_gd7_provider_result_chirho(
                &storage_chirho,
                &intent_state_chirho,
                &provider_chirho,
                payload_chirho,
            ),
            Err(Gd7CompensationCompositionRefusalChirho::ProcessingChirho(
                Gd7ObligationProcessingRefusalChirho::ResumeAttemptsExceededChirho,
            ))
        );
        assert_eq!(
            crate::reconciliation_chirho::load_gd7_obligation_processing_state_chirho(
                &storage_chirho,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("reload held attempt-limit state")
            .terminal_progress_chirho(),
            crate::reconciliation_chirho::Gd7ObligationTerminalProgressChirho::HeldManualChirho
        );
        fs::remove_dir_all(directory_chirho).expect("remove attempt limit storage");
    }

    #[test]
    fn resume_replays_same_key_and_payload_to_one_provider_effect_chirho() {
        let directory_chirho = std::env::temp_dir().join(format!(
            "cairn-gd7-provider-replay-{}-chirho",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory_chirho);
        fs::create_dir_all(&directory_chirho).expect("provider replay storage");
        let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&directory_chirho)
            .expect("open provider replay storage");
        let state_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "receipt-provider-replay-chirho",
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "inverse-provider-replay-chirho",
            "action-provider-replay-chirho",
        )
        .expect("create provider replay state");
        let provider_chirho = KeyHonoringProviderChirho::new_chirho();
        let payload_chirho = b"provider-replay-payload-chirho";

        arm_gd7_provider_failpoint_chirho("after-provider-before-observation-chirho");
        assert!(compose_gd7_provider_result_chirho(
            &storage_chirho,
            &state_chirho,
            &provider_chirho,
            payload_chirho,
        )
        .is_err());
        let intent_state_chirho =
            crate::reconciliation_chirho::load_gd7_obligation_processing_state_chirho(
                &storage_chirho,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("reload persisted intent");
        let resumed_chirho = compose_gd7_provider_result_chirho(
            &storage_chirho,
            &intent_state_chirho,
            &provider_chirho,
            payload_chirho,
        )
        .expect("resume key-idempotent provider call");
        assert_eq!(provider_chirho.calls_chirho.get(), 2);
        let keys_chirho = provider_chirho.keys_chirho.borrow();
        assert_eq!(keys_chirho.len(), 2);
        assert_eq!(keys_chirho[0], keys_chirho[1]);
        assert_eq!(
            resumed_chirho.provider_effect_id_chirho(),
            Some("same-provider-effect-chirho")
        );
        assert_eq!(resumed_chirho.provider_resume_attempts_chirho(), Some(1));
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn provider_key_is_deterministic_and_term_independent_chirho() {
        let first_chirho = derive_gd7_compensation_provider_idempotency_key_chirho(
            "obligation-digest-chirho",
            "action-001-chirho",
        )
        .expect("valid identity inputs produce a provider key");
        let second_chirho = derive_gd7_compensation_provider_idempotency_key_chirho(
            "obligation-digest-chirho",
            "action-001-chirho",
        )
        .expect("same identity inputs reproduce the provider key");
        assert_eq!(first_chirho, second_chirho);
        assert!(first_chirho.starts_with("gd7-compensation-provider-chirho:"));
    }

    #[test]
    fn provider_key_rejects_missing_identity_inputs_chirho() {
        assert_eq!(
            derive_gd7_compensation_provider_idempotency_key_chirho("", "action-001-chirho"),
            Err(Gd7CompensationProviderRefusalChirho::InvalidProviderKeyChirho)
        );
        assert_eq!(
            derive_gd7_compensation_provider_idempotency_key_chirho("obligation-digest-chirho", ""),
            Err(Gd7CompensationProviderRefusalChirho::InvalidProviderKeyChirho)
        );
    }
}
