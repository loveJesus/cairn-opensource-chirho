// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Dev-only served-LLM effect composition injected into the serve runtime: it owns one resident
//! journal handle plus the signers, provider, money policy, and billing kind, and builds a fresh
//! [`LocalLlmServedCompositionChirho`] per call inside a std `Mutex` (a disjoint-field borrow), so a
//! served DAG can drive the CF3 money ladder through the same effect coordinator the a2 direct-call
//! proof uses. It is the served-LLM sibling of `ledger_host_runtime_chirho`'s postgres shared
//! runtime, and it carries no A+ door: the caller hands it an already-open handle by value.

use anyhow::{bail, Result};
use cairn_chirho::effect_chirho::llm_served_chirho::{
    LlmServedMoneyPolicyPortChirho, LlmServedRuntimePortChirho, LocalLlmServedCompositionChirho,
};
use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_ledger_host_chirho::{
    require_test_kind_marked_host_config_chirho, HostLedgerSignersChirho,
    ResidentEffectJournalHandleChirho,
};
use cairn_ledger_model_chirho::ids_chirho::AssetKindIdChirho;
use cairn_llm_served_effect_chirho::LlmProviderChirho;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The typed refusals the shared served-LLM composition can raise before it ever reaches the ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LlmServedCompositionRefusalChirho {
    /// The one provider lock was poisoned by a panicking prior holder; fail closed rather than
    /// compose a fresh ladder over possibly-inconsistent owned state.
    ProviderLockUnavailableChirho,
}

impl fmt::Display for LlmServedCompositionRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::ProviderLockUnavailableChirho => {
                "configured served-LLM provider lock is unavailable"
            }
        })
    }
}

impl Error for LlmServedCompositionRefusalChirho {}

/// The startup-fence refusal identity raised when the root a dev served-LLM entry is asked to serve
/// is not the exact root the injected composition was bound to.
pub const SERVED_LLM_DEV_ROOT_MISMATCH_REFUSAL_CHIRHO: &str = "ServedLlmDevRootMismatchChirho";

/// The readiness-probe refusal raised when a served draft already holds the single composition lock.
/// The probe uses `try_lock` (never a blocking `lock`) so a concurrent request cannot occupy an async
/// worker for a draft's full provider duration; contention is this bounded typed refusal instead.
pub const SERVED_LLM_COMPOSITION_BUSY_REFUSAL_CHIRHO: &str = "ServedLlmCompositionBusyChirho";

/// The one explicitly composed served-app surface the dev served-LLM dispatch admits: an app name,
/// its render root (GET), and its single paid route (POST). Every other app or route falls through
/// to the UNCHANGED credits/relay dispatch — there is never a blanket `Some(composition)` exemption.
/// The name and route are cloned OUTSIDE the composition `Mutex` (see
/// [`SharedLlmServedCompositionChirho`]) so the per-request scope check is lock-free.
#[derive(Clone)]
pub struct ServedLlmCardSurfaceChirho {
    app_chirho: String,
    paid_route_chirho: String,
}

impl ServedLlmCardSurfaceChirho {
    /// Bind the served app name and its single paid route.
    pub fn new_chirho(app_chirho: impl Into<String>, paid_route_chirho: impl Into<String>) -> Self {
        Self {
            app_chirho: app_chirho.into(),
            paid_route_chirho: paid_route_chirho.into(),
        }
    }
}

/// The owned pieces one served-LLM ladder is composed from. Held behind the shared `Mutex` so a
/// fresh `LocalLlmServedCompositionChirho` can borrow the journal handle mutably and the signers,
/// policy, and provider immutably (disjoint fields) for exactly one call, then drop.
struct LlmServedOwnedRuntimeChirho {
    root_chirho: PathBuf,
    handle_chirho: ResidentEffectJournalHandleChirho,
    signers_chirho: HostLedgerSignersChirho,
    provider_chirho: Box<dyn LlmProviderChirho + Send>,
    policy_chirho: Box<dyn LlmServedMoneyPolicyPortChirho + Send>,
    billing_kind_chirho: AssetKindIdChirho,
}

/// A `Clone`, `Send + Sync + 'static` shared handle to the one served-LLM composition. The clone is
/// what the serve run path moves into `spawn_blocking` (mirror of the postgres shared runtime); the
/// `Arc<Mutex<..>>` serializes every served draft through the single owned journal handle.
#[derive(Clone)]
pub struct SharedLlmServedCompositionChirho {
    inner_chirho: Arc<Mutex<LlmServedOwnedRuntimeChirho>>,
    app_chirho: Arc<str>,
    paid_route_chirho: Arc<str>,
}

impl SharedLlmServedCompositionChirho {
    fn new_chirho(
        runtime_chirho: LlmServedOwnedRuntimeChirho,
        surface_chirho: &ServedLlmCardSurfaceChirho,
    ) -> Self {
        Self {
            inner_chirho: Arc::new(Mutex::new(runtime_chirho)),
            app_chirho: Arc::from(surface_chirho.app_chirho.as_str()),
            paid_route_chirho: Arc::from(surface_chirho.paid_route_chirho.as_str()),
        }
    }

    /// The one composed served app name (lock-free; immutable for the composition's lifetime).
    pub fn served_app_chirho(&self) -> &str {
        &self.app_chirho
    }

    /// The one composed paid route (lock-free; immutable for the composition's lifetime).
    pub fn paid_route_chirho(&self) -> &str {
        &self.paid_route_chirho
    }

    /// GAP-1 startup fence. Before the dev serve entry does any startup recovery, router build, or
    /// listener bind, the root it is about to serve must be the EXACT root this composition was bound
    /// to (canonical path equality), and that bound root's effective config must be test-kind marked.
    /// Env opt-in plus composition presence is therefore never the whole fence.
    pub fn verify_dev_startup_eligibility_chirho(&self, served_root_chirho: &Path) -> Result<()> {
        let owned_chirho = self.inner_chirho.lock().map_err(|_error_chirho| {
            LlmServedCompositionRefusalChirho::ProviderLockUnavailableChirho
        })?;
        let bound_root_chirho = owned_chirho.root_chirho.canonicalize()?;
        let served_root_canonical_chirho = served_root_chirho.canonicalize()?;
        if served_root_canonical_chirho != bound_root_chirho {
            bail!(
                "{SERVED_LLM_DEV_ROOT_MISMATCH_REFUSAL_CHIRHO}: the dev served-LLM entry was asked \
                 to serve a root the injected composition is not bound to"
            );
        }
        require_test_kind_marked_host_config_chirho(
            owned_chirho.handle_chirho.effective_ledger_config_chirho(),
        )
    }

    /// GAP-2 live-authority readiness. Derive local write authority from the resident actor's LIVE
    /// append-authority path (acquire and immediately drop the O(1) generation guard) rather than
    /// from a static era check or the runtime-binding recheck. A deposed / transferring / not-warm
    /// actor returns the same refusal identity the write path would, so a served paid draft can be
    /// refused before any body persistence when this node is not the current local authority.
    ///
    /// The composition lock is taken with `try_lock`, NEVER a blocking `lock`: this probe runs on an
    /// async worker (`app_http` calls it synchronously before `spawn_blocking`), and the same lock is
    /// held across a full draft's provider call in `with_composition_chirho`. A blocking acquire here
    /// would let one draft occupy an async worker for the provider's whole duration. Contention is a
    /// bounded typed refusal instead; the `Err` carries the specific reason for the server log.
    pub fn probe_local_authority_live_chirho(&self) -> Result<()> {
        let owned_chirho =
            self.inner_chirho
                .try_lock()
                .map_err(|error_chirho| match error_chirho {
                    std::sync::TryLockError::WouldBlock => anyhow::anyhow!(
                "{SERVED_LLM_COMPOSITION_BUSY_REFUSAL_CHIRHO}: a served draft already holds the \
                 composition"
            ),
                    std::sync::TryLockError::Poisoned(_) => {
                        LlmServedCompositionRefusalChirho::ProviderLockUnavailableChirho.into()
                    }
                })?;
        owned_chirho
            .handle_chirho
            .head_transition_authority_chirho()
            .probe_local_append_authority_live_chirho()
    }

    /// Build one `LocalLlmServedCompositionChirho` fresh inside the lock, run `call_chirho` against
    /// it as an `LlmServedRuntimePortChirho`, and drop it before releasing the lock. The composition
    /// borrows the owned fields disjointly, so the journal handle is the only mutable borrow.
    pub(crate) fn with_composition_chirho<OutputChirho>(
        &self,
        call_chirho: impl FnOnce(&mut dyn LlmServedRuntimePortChirho) -> Result<OutputChirho>,
    ) -> Result<OutputChirho> {
        let mut owned_chirho = self.inner_chirho.lock().map_err(|_error_chirho| {
            LlmServedCompositionRefusalChirho::ProviderLockUnavailableChirho
        })?;
        let LlmServedOwnedRuntimeChirho {
            root_chirho,
            handle_chirho,
            signers_chirho,
            provider_chirho,
            policy_chirho,
            billing_kind_chirho,
        } = &mut *owned_chirho;
        let mut composition_chirho = LocalLlmServedCompositionChirho::open_chirho(
            root_chirho.as_path(),
            handle_chirho,
            signers_chirho.effect_intent_signer_chirho(),
            signers_chirho.effect_terminal_signer_chirho(),
            &**policy_chirho,
            &**provider_chirho,
            billing_kind_chirho.clone(),
        )?;
        call_chirho(&mut composition_chirho)
    }
}

/// The injected pieces `open_shared_llm_served_composition_with_resident_journal_chirho` binds into one
/// served-LLM composition. Grouped in a struct (Finding 7 / clippy — a params struct, not a lint
/// suppression) so the opener takes a single parameter: the two borrows (`root_chirho`,
/// `ledger_config_chirho`) feed only the `verify_runtime_binding_chirho` precheck and are never stored,
/// while the owned pieces are moved into the composition. Fields are `pub` because the sole caller (the
/// a2b e2e test) lives in another crate.
pub struct OpenSharedLlmServedCompositionParamsChirho<'binding_chirho> {
    /// The dev root this composition is bound to; identity-rechecked, then stored as owned.
    pub root_chirho: &'binding_chirho Path,
    /// The ALREADY-OPEN resident journal handle, taken by value (the serve crate never names the
    /// test-kind A+ door, so it stays clear of the door-confinement guard).
    pub handle_chirho: ResidentEffectJournalHandleChirho,
    /// The host ledger signers moved into the composition.
    pub signers_chirho: HostLedgerSignersChirho,
    /// The LLM provider (a stub in a2b) moved into the composition.
    pub provider_chirho: Box<dyn LlmProviderChirho + Send>,
    /// The user-pays money policy moved into the composition.
    pub policy_chirho: Box<dyn LlmServedMoneyPolicyPortChirho + Send>,
    /// The billing asset kind moved into the composition.
    pub billing_kind_chirho: AssetKindIdChirho,
    /// The effective ledger config; consumed only by the runtime-binding precheck, never stored.
    pub ledger_config_chirho: &'binding_chirho LedgerHostConfigChirho,
    /// The one served app plus paid route this composition answers for.
    pub served_surface_chirho: ServedLlmCardSurfaceChirho,
}

/// Compose the served-LLM effect runtime around an ALREADY-OPEN resident journal handle.
///
/// The handle is taken by value: this function never names the test-kind A+ door, so the serve crate
/// stays clear of the door-confinement guard. Root and full typed config equality are rechecked
/// through `verify_runtime_binding_chirho` FIRST — before the provider, policy, or billing kind can
/// be paired with that actor — mirroring the postgres `..._with_resident_journal_chirho` opener. The
/// params destructure is a pure move, so the recheck still runs before any composition state exists.
pub fn open_shared_llm_served_composition_with_resident_journal_chirho(
    params_chirho: OpenSharedLlmServedCompositionParamsChirho<'_>,
) -> Result<SharedLlmServedCompositionChirho> {
    let OpenSharedLlmServedCompositionParamsChirho {
        root_chirho,
        handle_chirho,
        signers_chirho,
        provider_chirho,
        policy_chirho,
        billing_kind_chirho,
        ledger_config_chirho,
        served_surface_chirho,
    } = params_chirho;
    handle_chirho.verify_runtime_binding_chirho(root_chirho, ledger_config_chirho)?;
    Ok(SharedLlmServedCompositionChirho::new_chirho(
        LlmServedOwnedRuntimeChirho {
            root_chirho: root_chirho.to_path_buf(),
            handle_chirho,
            signers_chirho,
            provider_chirho,
            policy_chirho,
            billing_kind_chirho,
        },
        &served_surface_chirho,
    ))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn assert_send_chirho<T: Send>() {}
    fn assert_sync_chirho<T: Sync>() {}

    // Q5: the shared composition is cloned and moved into `spawn_blocking`, so it must be
    // `Send + Sync + 'static`. This is the definitive static proof, not an inference from field
    // types: it fails to compile the day any owned piece stops being `Send`.
    #[test]
    fn shared_llm_served_composition_is_send_sync_for_spawn_blocking_chirho() {
        assert_send_chirho::<SharedLlmServedCompositionChirho>();
        assert_sync_chirho::<SharedLlmServedCompositionChirho>();
    }
}
