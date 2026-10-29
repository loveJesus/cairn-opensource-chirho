// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Same-process append admission for one concrete `RaftWriterElectorChirho` instance.
//!
//! The public read-only handle has no independent constructor and accepts no consistency group. The elector
//! creates the private publisher and its paired handle together, then publishes a fixed-field authority
//! observation after each locally completed Raft transition. Append admission is expected O(1): fixed
//! atomic reads, one `Mutex::try_lock`, and fixed-field checks. It never locks `RawNode`, walks
//! membership, or performs I/O.
//!
//! This guard seals only locally observed transitions. It cannot observe an unseen remote higher term
//! and is not a durable or cross-host fence. GD7 winner selection and losing-fork compensation remain
//! mandatory.

use crate::elector_port_chirho::NodeIdChirho;
use crate::monotonic_clock_chirho::MonotonicClockChirho;
use cairn_core_chirho::model_chirho::ConsistencyGroupIdChirho;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

/// The fixed fields published after a successful local Raft transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalAppendAuthorityObservationChirho {
    pub(crate) local_is_leader_chirho: bool,
    pub(crate) warmup_lease_valid_chirho: bool,
    /// The monotonic confirmation paired with this observation. Zero for legacy tick-only leases.
    pub(crate) lease_confirmed_millis_chirho: u64,
    pub(crate) local_is_promotable_voter_chirho: bool,
    pub(crate) transfer_in_progress_chirho: bool,
    /// The Raft term published with this completed local transition. Durable electors persist it
    /// before publication; ephemeral electors intentionally do not promise restart persistence.
    pub(crate) published_raft_term_chirho: u64,
}

/// Why a local append-generation guard was not issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum LocalAppendAuthorityRefusalChirho {
    /// A Raft transition announced itself before this acquisition completed.
    TransitionPendingChirho,
    /// Another append guard currently seals the same local authority generation.
    GuardBusyChirho,
    /// A transition failed or panicked; only elector reconstruction may mint a new authority pair.
    AuthorityPoisonedChirho,
    /// The exact elector instance that owned this handle has been dropped.
    ElectorDroppedChirho,
    /// No successful local transition has published a usable observation.
    AuthorityUnavailableChirho,
    /// The exact elector instance is not the local leader.
    NotLocalLeaderChirho,
    /// Leadership has not warmed or its monotonic confirmation has expired.
    WarmupLeaseInvalidChirho,
    /// The local member is not currently a promotable voter.
    NotPromotableVoterChirho,
    /// Raft is transferring leadership away from this member.
    LeadershipTransferInProgressChirho,
    /// A durable GD7 winner-handoff attempt currently freezes normal local appends.
    HandoffActiveChirho,
    /// A handoff operation named a different active attempt.
    HandoffIdentityMismatchChirho,
    /// A handoff operation did not name one canonical lowercase digest.
    InvalidHandoffIdentityChirho,
    /// The process-local handoff activation generation cannot advance without wrapping.
    HandoffGenerationExhaustedChirho,
    /// The published Raft term cannot fit the writer-fence composite-term representation.
    PublishedRaftTermOutOfRangeChirho,
}

impl fmt::Display for LocalAppendAuthorityRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason_chirho = match self {
            Self::TransitionPendingChirho => "a local Raft transition is pending",
            Self::GuardBusyChirho => "the local append-authority guard is busy",
            Self::AuthorityPoisonedChirho => {
                "the local append-authority state is terminally poisoned; reconstruct the elector"
            }
            Self::ElectorDroppedChirho => "the owning Raft elector has been dropped",
            Self::AuthorityUnavailableChirho => {
                "no successful local Raft transition has published append authority"
            }
            Self::NotLocalLeaderChirho => "this elector instance is not the local leader",
            Self::WarmupLeaseInvalidChirho => "the local leadership lease is not warm and live",
            Self::NotPromotableVoterChirho => "the local member is not a promotable voter",
            Self::LeadershipTransferInProgressChirho => "local leadership transfer is in progress",
            Self::HandoffActiveChirho => {
                "a durable GD7 winner handoff currently freezes local appends"
            }
            Self::HandoffIdentityMismatchChirho => {
                "the GD7 winner-handoff attempt differs from the active attempt"
            }
            Self::InvalidHandoffIdentityChirho => {
                "the GD7 winner-handoff attempt identity is invalid"
            }
            Self::HandoffGenerationExhaustedChirho => {
                "the process-local handoff activation generation is exhausted"
            }
            Self::PublishedRaftTermOutOfRangeChirho => {
                "the published Raft term is outside the writer-fence u32 range"
            }
        };
        formatter_chirho.write_str(reason_chirho)
    }
}

impl Error for LocalAppendAuthorityRefusalChirho {}

/// A cloneable, bounded reference to the append authority owned by one exact elector instance.
///
/// It has no independent constructor. Host composition obtains it from
/// `RaftWriterElectorChirho::local_append_authority_handle_chirho`, with no caller-supplied group.
#[derive(Clone)]
pub struct LocalAppendAuthorityHandleChirho {
    shared_chirho: Arc<LocalAppendAuthoritySharedChirho>,
}

impl LocalAppendAuthorityHandleChirho {
    /// Try to seal the currently published local authority generation without waiting.
    ///
    /// The pre/post pending checks close the race with a transition announcing itself while this method
    /// acquires the gate. A returned guard holds the gate until drop, so a local Raft transition waits
    /// for the in-flight append operation and new acquisitions refuse while it waits.
    pub fn try_acquire_chirho(
        &self,
    ) -> Result<LocalLeadershipGenerationGuardChirho<'_>, LocalAppendAuthorityRefusalChirho> {
        let state_guard_chirho = self.try_lock_current_state_chirho()?;
        if state_guard_chirho.active_handoff_digest_chirho.is_some() {
            return Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho);
        }
        let observation_chirho = state_guard_chirho
            .published_observation_chirho
            .ok_or(LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho)?;
        validate_observation_chirho(&self.shared_chirho, observation_chirho)?;
        let process_generation_chirho = state_guard_chirho.process_generation_chirho;

        Ok(LocalLeadershipGenerationGuardChirho {
            state_guard_chirho,
            shared_chirho: &self.shared_chirho,
            process_generation_chirho,
            published_raft_term_chirho: observation_chirho.published_raft_term_chirho,
        })
    }

    #[cfg(test)]
    pub(crate) fn begin_transition_for_test_chirho(
        &self,
    ) -> LocalAppendAuthorityTransitionChirho<'_> {
        begin_transition_chirho(&self.shared_chirho)
    }

    /// Acquire the generation gate for a new handoff without activating it yet.
    ///
    /// The caller may create immutable evidence while this guard is held. It must durably publish
    /// its `Preparing` checkpoint before calling `activate_chirho`; activation then sets the
    /// in-memory marker without releasing the mutex, closing the append gap between those actions.
    pub fn try_prepare_handoff_chirho(
        &self,
        handoff_digest_chirho: &str,
    ) -> Result<LocalAppendHandoffPreparationChirho<'_>, LocalAppendAuthorityRefusalChirho> {
        validate_handoff_digest_chirho(handoff_digest_chirho)?;
        let mut state_guard_chirho = self.try_lock_current_state_chirho()?;
        if state_guard_chirho.active_handoff_digest_chirho.is_some() {
            return Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho);
        }
        let observation_chirho = state_guard_chirho
            .published_observation_chirho
            .ok_or(LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho)?;
        validate_observation_chirho(&self.shared_chirho, observation_chirho)?;
        let process_generation_chirho = state_guard_chirho.process_generation_chirho;
        let handoff_activation_generation_chirho =
            reserve_handoff_activation_generation_chirho(&mut state_guard_chirho)?;
        Ok(LocalAppendHandoffPreparationChirho {
            state_guard_chirho,
            handoff_digest_chirho: handoff_digest_chirho.to_owned(),
            consistency_group_chirho: self.shared_chirho.consistency_group_chirho.clone(),
            node_id_chirho: self.shared_chirho.node_id_chirho.clone(),
            process_generation_chirho,
            published_raft_term_chirho: observation_chirho.published_raft_term_chirho,
            handoff_activation_generation_chirho,
        })
    }

    /// Reacquire the generation gate only for the exact active handoff.
    ///
    /// Leadership drift refuses this guard but leaves the active marker in place, so an uncertain
    /// handoff cannot silently fall back to ordinary appends.
    pub fn try_acquire_handoff_chirho(
        &self,
        handoff_digest_chirho: &str,
    ) -> Result<LocalAppendHandoffGenerationGuardChirho<'_>, LocalAppendAuthorityRefusalChirho>
    {
        validate_handoff_digest_chirho(handoff_digest_chirho)?;
        let state_guard_chirho = self.try_lock_current_state_chirho()?;
        match state_guard_chirho.active_handoff_digest_chirho.as_deref() {
            Some(active_chirho) if active_chirho == handoff_digest_chirho => {}
            Some(_active_chirho) => {
                return Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho);
            }
            None => return Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho),
        }
        let observation_chirho = state_guard_chirho
            .published_observation_chirho
            .ok_or(LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho)?;
        validate_observation_chirho(&self.shared_chirho, observation_chirho)?;
        let process_generation_chirho = state_guard_chirho.process_generation_chirho;
        state_guard_chirho
            .active_handoff_generation_chirho
            .ok_or(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho)?;
        Ok(LocalAppendHandoffGenerationGuardChirho {
            _state_guard_chirho: state_guard_chirho,
            handoff_digest_chirho: handoff_digest_chirho.to_owned(),
            consistency_group_chirho: self.shared_chirho.consistency_group_chirho.clone(),
            node_id_chirho: self.shared_chirho.node_id_chirho.clone(),
            process_generation_chirho,
            published_raft_term_chirho: observation_chirho.published_raft_term_chirho,
        })
    }

    /// Reacquire the generation gate for the ONE mutation lane admitted while a handoff is active.
    ///
    /// GD7 winner-side compensation, ruled (a) by L.J. 2026-08-05. An accepted winner handoff
    /// freezes ordinary appends; the fenced compensation append is the single leg that unstrands the
    /// group's money path, and under that ruling it lands on the LIVE WINNER's journal under the
    /// winner's own term. This method is what narrows the marker's totality by exactly that lane,
    /// and it is narrowed three ways at once: the caller must name the EXACT active attempt (a
    /// mismatch or an absent marker refuses, never falls back), the observation is validated on the
    /// same terms as an ordinary acquisition, and the returned guard carries NO release authority.
    ///
    /// That last property is the point: [`LocalAppendHandoffGenerationGuardChirho::release_chirho`]
    /// exists so the handoff's OWN evidence work can retire its marker, and this lane must never be
    /// able to do that. It borrows the freeze; it cannot clear it.
    pub fn try_acquire_active_handoff_append_chirho(
        &self,
        handoff_digest_chirho: &str,
    ) -> Result<LocalActiveHandoffAppendGenerationGuardChirho<'_>, LocalAppendAuthorityRefusalChirho>
    {
        validate_handoff_digest_chirho(handoff_digest_chirho)?;
        let state_guard_chirho = self.try_lock_current_state_chirho()?;
        match state_guard_chirho.active_handoff_digest_chirho.as_deref() {
            Some(active_chirho) if active_chirho == handoff_digest_chirho => {}
            Some(_) | None => {
                return Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho);
            }
        }
        let observation_chirho = state_guard_chirho
            .published_observation_chirho
            .ok_or(LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho)?;
        validate_observation_chirho(&self.shared_chirho, observation_chirho)?;
        state_guard_chirho
            .active_handoff_generation_chirho
            .ok_or(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho)?;
        let process_generation_chirho = state_guard_chirho.process_generation_chirho;
        Ok(LocalActiveHandoffAppendGenerationGuardChirho {
            _state_guard_chirho: state_guard_chirho,
            process_generation_chirho,
            published_raft_term_chirho: observation_chirho.published_raft_term_chirho,
        })
    }

    /// Seal the published generation for resident STARTUP, whether or not a handoff freeze is active.
    ///
    /// Startup READS coordinates; it never appends. Ordinary acquisition refuses
    /// `HandoffActiveChirho` before validating anything, so before the GD7 resume step a frozen
    /// winner could not even OPEN its resident authority — which is why the winner could not be the
    /// node that carries its own compensation. This method applies exactly the same observation
    /// validation and holds exactly the same mutex as [`Self::try_acquire_chirho`]; the ONLY
    /// difference is that an active handoff marker does not refuse it.
    ///
    /// The distinct return type is the confinement: no append path accepts it, so admitting startup
    /// under a freeze cannot become admitting a WRITE under a freeze. Startup must come up
    /// handoff-aware, never by exempting startup writes.
    pub fn try_acquire_startup_coordinates_chirho(
        &self,
    ) -> Result<LocalStartupCoordinatesGuardChirho<'_>, LocalAppendAuthorityRefusalChirho> {
        let state_guard_chirho = self.try_lock_current_state_chirho()?;
        let observation_chirho = state_guard_chirho
            .published_observation_chirho
            .ok_or(LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho)?;
        validate_observation_chirho(&self.shared_chirho, observation_chirho)?;
        let process_generation_chirho = state_guard_chirho.process_generation_chirho;
        Ok(LocalStartupCoordinatesGuardChirho {
            _state_guard_chirho: state_guard_chirho,
            process_generation_chirho,
            published_raft_term_chirho: observation_chirho.published_raft_term_chirho,
        })
    }

    /// Attenuate this authority handle to the one read-only handoff observation needed by replicas
    /// and migration fencing. The returned type has no path back to this broader handle.
    pub fn handoff_read_handle_chirho(&self) -> LocalAppendHandoffReadHandleChirho {
        LocalAppendHandoffReadHandleChirho {
            shared_chirho: Arc::clone(&self.shared_chirho),
        }
    }

    /// Attenuate this authority handle to handoff-marker control without either append lane.
    ///
    /// The returned type can prepare or restore a marker and can release only a previously observed
    /// exact activation generation. It cannot acquire ordinary append authority, acquire the GD7
    /// compensation append lane, campaign, tick, dereference, or recover this broad handle.
    pub fn handoff_control_handle_chirho(&self) -> LocalAppendHandoffControlHandleChirho {
        LocalAppendHandoffControlHandleChirho {
            inner_chirho: self.clone(),
        }
    }

    /// Snapshot one exact active handoff generation for read-only resident views.
    ///
    /// Unlike the mutation/revalidation guard, this witness does not retain the authority mutex
    /// while a potentially growing read executes. No append path accepts this distinct type.
    pub fn try_acquire_handoff_read_chirho(
        &self,
        handoff_digest_chirho: &str,
    ) -> Result<LocalAppendHandoffReadGenerationChirho, LocalAppendAuthorityRefusalChirho> {
        self.handoff_read_handle_chirho()
            .try_acquire_handoff_read_chirho(handoff_digest_chirho)
    }

    /// Restore a durable active handoff before exposing the reconstructed resident actor.
    ///
    /// This operation deliberately does not require current leadership. A stale or unavailable
    /// observation must preserve the freeze; only later exact-attempt recovery may release it.
    pub fn restore_handoff_chirho(
        &self,
        handoff_digest_chirho: &str,
    ) -> Result<(), LocalAppendAuthorityRefusalChirho> {
        validate_handoff_digest_chirho(handoff_digest_chirho)?;
        let mut state_guard_chirho = self.try_lock_current_state_chirho()?;
        match state_guard_chirho.active_handoff_digest_chirho.as_deref() {
            Some(active_chirho) if active_chirho == handoff_digest_chirho => state_guard_chirho
                .active_handoff_generation_chirho
                .ok_or(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho)
                .map(|_generation_chirho| ()),
            Some(_active_chirho) => {
                Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho)
            }
            None => {
                let handoff_activation_generation_chirho =
                    reserve_handoff_activation_generation_chirho(&mut state_guard_chirho)?;
                state_guard_chirho.active_handoff_digest_chirho =
                    Some(handoff_digest_chirho.to_owned());
                state_guard_chirho.active_handoff_generation_chirho =
                    Some(handoff_activation_generation_chirho);
                Ok(())
            }
        }
    }

    /// The exact consistency group bound when the owning elector was constructed.
    pub fn consistency_group_chirho(&self) -> &ConsistencyGroupIdChirho {
        &self.shared_chirho.consistency_group_chirho
    }

    /// The exact node identity bound when the owning elector was constructed.
    pub fn node_id_chirho(&self) -> &NodeIdChirho {
        &self.shared_chirho.node_id_chirho
    }

    fn try_lock_current_state_chirho(
        &self,
    ) -> Result<MutexGuard<'_, LocalAppendAuthorityStateChirho>, LocalAppendAuthorityRefusalChirho>
    {
        try_lock_current_state_chirho(&self.shared_chirho)
    }

    #[cfg(test)]
    pub(crate) fn transition_pending_count_chirho(&self) -> usize {
        self.shared_chirho
            .transition_pending_chirho
            .load(Ordering::Acquire)
    }
}

/// Marker-only control capability attenuated from one exact local append authority.
///
/// The private field has no accessor and this type implements no conversion or dereference back to
/// [`LocalAppendAuthorityHandleChirho`]. Its method set is the complete mutation surface available
/// to durable migration recovery: marker preparation, exact active-owner restoration, read-only
/// observation, and release of the same observed activation lifetime.
#[derive(Clone)]
pub struct LocalAppendHandoffControlHandleChirho {
    inner_chirho: LocalAppendAuthorityHandleChirho,
}

impl LocalAppendHandoffControlHandleChirho {
    pub fn try_prepare_handoff_chirho(
        &self,
        handoff_digest_chirho: &str,
    ) -> Result<LocalAppendHandoffPreparationChirho<'_>, LocalAppendAuthorityRefusalChirho> {
        self.inner_chirho
            .try_prepare_handoff_chirho(handoff_digest_chirho)
    }

    /// Restore one durable ACTIVE owner before the resident actor is exposed.
    ///
    /// This is never an ownership-discovery operation. The caller must already have verified an
    /// active signed checkpoint; a foreign live marker refuses without mutation.
    pub fn restore_handoff_chirho(
        &self,
        handoff_digest_chirho: &str,
    ) -> Result<(), LocalAppendAuthorityRefusalChirho> {
        self.inner_chirho
            .restore_handoff_chirho(handoff_digest_chirho)
    }

    pub fn handoff_read_handle_chirho(&self) -> LocalAppendHandoffReadHandleChirho {
        self.inner_chirho.handoff_read_handle_chirho()
    }

    /// Reacquire marker control only if every observed owner/lifetime coordinate is still exact.
    ///
    /// Terminal recovery first discovers ownership with the read-only handle and only then calls
    /// this method. The activation-generation comparison closes same-digest ABA between those two
    /// operations; an absent, foreign, or reactivated marker refuses and remains untouched.
    pub fn try_acquire_observed_handoff_chirho(
        &self,
        observed_chirho: &LocalAppendHandoffReadGenerationChirho,
    ) -> Result<LocalAppendHandoffGenerationGuardChirho<'_>, LocalAppendAuthorityRefusalChirho>
    {
        let state_guard_chirho = self.inner_chirho.try_lock_current_state_chirho()?;
        if state_guard_chirho.active_handoff_digest_chirho.as_deref()
            != Some(observed_chirho.handoff_digest_chirho())
            || state_guard_chirho.active_handoff_generation_chirho
                != Some(observed_chirho.handoff_activation_generation_chirho())
            || self.inner_chirho.consistency_group_chirho()
                != observed_chirho.consistency_group_chirho()
            || self.inner_chirho.node_id_chirho() != observed_chirho.node_id_chirho()
            || state_guard_chirho.process_generation_chirho
                != observed_chirho.process_generation_chirho()
        {
            return Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho);
        }
        let observation_chirho = state_guard_chirho
            .published_observation_chirho
            .ok_or(LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho)?;
        validate_observation_chirho(&self.inner_chirho.shared_chirho, observation_chirho)?;
        if observation_chirho.published_raft_term_chirho
            != observed_chirho.published_raft_term_chirho()
        {
            return Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho);
        }
        Ok(LocalAppendHandoffGenerationGuardChirho {
            _state_guard_chirho: state_guard_chirho,
            handoff_digest_chirho: observed_chirho.handoff_digest_chirho().to_owned(),
            consistency_group_chirho: observed_chirho.consistency_group_chirho().clone(),
            node_id_chirho: observed_chirho.node_id_chirho().clone(),
            process_generation_chirho: observed_chirho.process_generation_chirho(),
            published_raft_term_chirho: observed_chirho.published_raft_term_chirho(),
        })
    }

    /// Release only a marker first observed as this exact owner and activation lifetime.
    ///
    /// An absent or foreign marker is left untouched and returns `Ok(false)`. Once an exact owner
    /// has been observed, any intervening release/reactivation is an ABA conflict and refuses
    /// rather than treating the replacement as the marker that was inspected.
    pub fn release_if_observed_owner_chirho(
        &self,
        handoff_digest_chirho: &str,
    ) -> Result<bool, LocalAppendAuthorityRefusalChirho> {
        let observed_chirho = match self
            .handoff_read_handle_chirho()
            .try_acquire_handoff_read_chirho(handoff_digest_chirho)
        {
            Ok(observed_chirho) => observed_chirho,
            Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho) => {
                return Ok(false);
            }
            Err(refusal_chirho) => return Err(refusal_chirho),
        };
        self.try_acquire_observed_handoff_chirho(&observed_chirho)?
            .release_chirho();
        Ok(true)
    }

    pub fn consistency_group_chirho(&self) -> &ConsistencyGroupIdChirho {
        self.inner_chirho.consistency_group_chirho()
    }

    pub fn node_id_chirho(&self) -> &NodeIdChirho {
        self.inner_chirho.node_id_chirho()
    }
}

impl fmt::Debug for LocalAppendHandoffControlHandleChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("LocalAppendHandoffControlHandleChirho")
            .finish_non_exhaustive()
    }
}

/// Read-only capability for observing one exact active handoff generation.
///
/// The shared state is private, and this type intentionally exposes no accessor, dereference,
/// conversion, append acquisition, marker preparation, activation, restoration, or release path.
pub struct LocalAppendHandoffReadHandleChirho {
    shared_chirho: Arc<LocalAppendAuthoritySharedChirho>,
}

impl LocalAppendHandoffReadHandleChirho {
    /// Require the exact shared authority slot to contain no active handoff marker.
    ///
    /// This read-only probe grants no marker identity and cannot prepare, activate, restore, or
    /// release a marker. Recovery uses it before staging any imported durable byte so an existing
    /// GD7 or migration owner cannot be mistaken for an available slot.
    pub fn require_no_active_handoff_chirho(
        &self,
    ) -> Result<(), LocalAppendAuthorityRefusalChirho> {
        let state_guard_chirho = try_lock_current_state_chirho(&self.shared_chirho)?;
        match (
            state_guard_chirho.active_handoff_digest_chirho.as_ref(),
            state_guard_chirho.active_handoff_generation_chirho,
        ) {
            (None, None) => Ok(()),
            (Some(_), Some(_)) => Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho),
            (None, Some(_)) | (Some(_), None) => {
                Err(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho)
            }
        }
    }

    /// Snapshot the currently active exact-attempt marker and validated local authority generation.
    pub fn try_acquire_handoff_read_chirho(
        &self,
        handoff_digest_chirho: &str,
    ) -> Result<LocalAppendHandoffReadGenerationChirho, LocalAppendAuthorityRefusalChirho> {
        validate_handoff_digest_chirho(handoff_digest_chirho)?;
        let state_guard_chirho = try_lock_current_state_chirho(&self.shared_chirho)?;
        match state_guard_chirho.active_handoff_digest_chirho.as_deref() {
            Some(active_chirho) if active_chirho == handoff_digest_chirho => {}
            Some(_) | None => {
                return Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho);
            }
        }
        let observation_chirho = state_guard_chirho
            .published_observation_chirho
            .ok_or(LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho)?;
        validate_observation_chirho(&self.shared_chirho, observation_chirho)?;
        let handoff_activation_generation_chirho = state_guard_chirho
            .active_handoff_generation_chirho
            .ok_or(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho)?;
        Ok(LocalAppendHandoffReadGenerationChirho {
            handoff_digest_chirho: handoff_digest_chirho.to_owned(),
            consistency_group_chirho: self.shared_chirho.consistency_group_chirho.clone(),
            node_id_chirho: self.shared_chirho.node_id_chirho.clone(),
            process_generation_chirho: state_guard_chirho.process_generation_chirho,
            published_raft_term_chirho: observation_chirho.published_raft_term_chirho,
            handoff_activation_generation_chirho,
        })
    }
}

impl fmt::Debug for LocalAppendHandoffReadHandleChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("LocalAppendHandoffReadHandleChirho")
            .finish_non_exhaustive()
    }
}

fn try_lock_current_state_chirho(
    shared_chirho: &LocalAppendAuthoritySharedChirho,
) -> Result<MutexGuard<'_, LocalAppendAuthorityStateChirho>, LocalAppendAuthorityRefusalChirho> {
    if !shared_chirho.elector_alive_chirho.load(Ordering::Acquire) {
        return Err(LocalAppendAuthorityRefusalChirho::ElectorDroppedChirho);
    }
    if shared_chirho
        .terminal_failure_chirho
        .load(Ordering::Acquire)
    {
        return Err(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho);
    }
    if shared_chirho
        .transition_pending_chirho
        .load(Ordering::Acquire)
        != 0
    {
        return Err(LocalAppendAuthorityRefusalChirho::TransitionPendingChirho);
    }
    let state_guard_chirho = match shared_chirho.state_chirho.try_lock() {
        Ok(state_guard_chirho) => state_guard_chirho,
        Err(TryLockError::WouldBlock) => {
            return Err(
                if shared_chirho
                    .transition_pending_chirho
                    .load(Ordering::Acquire)
                    != 0
                {
                    LocalAppendAuthorityRefusalChirho::TransitionPendingChirho
                } else {
                    LocalAppendAuthorityRefusalChirho::GuardBusyChirho
                },
            );
        }
        Err(TryLockError::Poisoned(_)) => {
            return Err(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho);
        }
    };
    if shared_chirho
        .transition_pending_chirho
        .load(Ordering::Acquire)
        != 0
    {
        return Err(LocalAppendAuthorityRefusalChirho::TransitionPendingChirho);
    }
    if !shared_chirho.elector_alive_chirho.load(Ordering::Acquire) {
        return Err(LocalAppendAuthorityRefusalChirho::ElectorDroppedChirho);
    }
    if shared_chirho
        .terminal_failure_chirho
        .load(Ordering::Acquire)
    {
        return Err(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho);
    }
    Ok(state_guard_chirho)
}

/// A non-cloneable, naturally non-`Send` RAII seal over one local generation.
///
/// `MutexGuard` supplies the non-`Send` property and holds the transition gate for the append operation.
pub struct LocalLeadershipGenerationGuardChirho<'a> {
    state_guard_chirho: MutexGuard<'a, LocalAppendAuthorityStateChirho>,
    shared_chirho: &'a LocalAppendAuthoritySharedChirho,
    process_generation_chirho: u64,
    published_raft_term_chirho: u64,
}

impl LocalLeadershipGenerationGuardChirho<'_> {
    /// Recheck held authority without reacquiring the transition gate or reading Raft.
    /// The gate freezes the published observation, not time: a monotonic lease still expires.
    /// Tick-only shadow leases retain their existing behavior. This check cannot cancel I/O
    /// that crosses the deadline after it returns, nor discover an unseen remote term.
    /// Workflow: spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/run-admission-chirho/held-lease-chirho/workflow-chirho.md.
    pub fn validate_current_chirho(&self) -> Result<(), LocalAppendAuthorityRefusalChirho> {
        if !self
            .shared_chirho
            .elector_alive_chirho
            .load(Ordering::Acquire)
        {
            return Err(LocalAppendAuthorityRefusalChirho::ElectorDroppedChirho);
        }
        if self
            .shared_chirho
            .terminal_failure_chirho
            .load(Ordering::Acquire)
        {
            return Err(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho);
        }
        let observation_chirho = self
            .state_guard_chirho
            .published_observation_chirho
            .ok_or(LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho)?;
        validate_observation_chirho(self.shared_chirho, observation_chirho)
    }

    /// The process-local generation for this exact elector instance.
    pub fn process_generation_chirho(&self) -> u64 {
        self.process_generation_chirho
    }

    /// The Raft term published with this generation.
    pub fn published_raft_term_chirho(&self) -> u64 {
        self.published_raft_term_chirho
    }
}

/// Exact-attempt generation gate for the ONE append lane admitted under an ACTIVE handoff.
///
/// Deliberately NOT [`LocalLeadershipGenerationGuardChirho`]. That type's name asserts an
/// acquisition made with no active handoff, and this is precisely the opposite acquisition; reusing
/// it would leave a name promising a guarantee it no longer holds. It exposes only the two
/// coordinates an append needs, and — unlike [`LocalAppendHandoffGenerationGuardChirho`] — it has no
/// `release_chirho`, so the compensation lane can never retire the marker it appends under.
pub struct LocalActiveHandoffAppendGenerationGuardChirho<'a> {
    _state_guard_chirho: MutexGuard<'a, LocalAppendAuthorityStateChirho>,
    process_generation_chirho: u64,
    published_raft_term_chirho: u64,
}

impl LocalActiveHandoffAppendGenerationGuardChirho<'_> {
    /// The process-local generation for this exact elector instance.
    pub fn process_generation_chirho(&self) -> u64 {
        self.process_generation_chirho
    }

    /// The Raft term published with this generation.
    pub fn published_raft_term_chirho(&self) -> u64 {
        self.published_raft_term_chirho
    }
}

/// Coordinate-only generation seal for resident startup, admitted with or without a handoff freeze.
///
/// It holds the same mutex an ordinary acquisition does, so a Raft transition still waits for the
/// bracket that opens a resident. It yields NEITHER append nor release authority: no append path
/// accepts this type, and it cannot touch the handoff marker in either direction.
pub struct LocalStartupCoordinatesGuardChirho<'a> {
    _state_guard_chirho: MutexGuard<'a, LocalAppendAuthorityStateChirho>,
    process_generation_chirho: u64,
    published_raft_term_chirho: u64,
}

impl LocalStartupCoordinatesGuardChirho<'_> {
    /// The process-local generation for this exact elector instance.
    pub fn process_generation_chirho(&self) -> u64 {
        self.process_generation_chirho
    }

    /// The Raft term published with this generation.
    pub fn published_raft_term_chirho(&self) -> u64 {
        self.published_raft_term_chirho
    }
}

/// Generation gate held while one durable handoff checkpoint is prepared.
pub struct LocalAppendHandoffPreparationChirho<'a> {
    state_guard_chirho: MutexGuard<'a, LocalAppendAuthorityStateChirho>,
    handoff_digest_chirho: String,
    consistency_group_chirho: ConsistencyGroupIdChirho,
    node_id_chirho: NodeIdChirho,
    process_generation_chirho: u64,
    published_raft_term_chirho: u64,
    handoff_activation_generation_chirho: u64,
}

impl<'a> LocalAppendHandoffPreparationChirho<'a> {
    pub fn handoff_digest_chirho(&self) -> &str {
        &self.handoff_digest_chirho
    }

    pub fn consistency_group_chirho(&self) -> &ConsistencyGroupIdChirho {
        &self.consistency_group_chirho
    }

    pub fn node_id_chirho(&self) -> &NodeIdChirho {
        &self.node_id_chirho
    }

    pub fn process_generation_chirho(&self) -> u64 {
        self.process_generation_chirho
    }

    /// The Raft term published with the generation held for this preparation.
    pub fn published_raft_term_chirho(&self) -> u64 {
        self.published_raft_term_chirho
    }

    /// Activate the attempt without releasing the generation mutex.
    pub fn activate_chirho(mut self) -> LocalAppendHandoffGenerationGuardChirho<'a> {
        self.state_guard_chirho.active_handoff_digest_chirho =
            Some(self.handoff_digest_chirho.clone());
        self.state_guard_chirho.active_handoff_generation_chirho =
            Some(self.handoff_activation_generation_chirho);
        LocalAppendHandoffGenerationGuardChirho {
            _state_guard_chirho: self.state_guard_chirho,
            handoff_digest_chirho: self.handoff_digest_chirho,
            consistency_group_chirho: self.consistency_group_chirho,
            node_id_chirho: self.node_id_chirho,
            process_generation_chirho: self.process_generation_chirho,
            published_raft_term_chirho: self.published_raft_term_chirho,
        }
    }
}

/// Exact-attempt generation gate while a durable handoff marker remains active.
pub struct LocalAppendHandoffGenerationGuardChirho<'a> {
    _state_guard_chirho: MutexGuard<'a, LocalAppendAuthorityStateChirho>,
    handoff_digest_chirho: String,
    consistency_group_chirho: ConsistencyGroupIdChirho,
    node_id_chirho: NodeIdChirho,
    process_generation_chirho: u64,
    published_raft_term_chirho: u64,
}

impl LocalAppendHandoffGenerationGuardChirho<'_> {
    pub fn handoff_digest_chirho(&self) -> &str {
        &self.handoff_digest_chirho
    }

    pub fn consistency_group_chirho(&self) -> &ConsistencyGroupIdChirho {
        &self.consistency_group_chirho
    }

    pub fn node_id_chirho(&self) -> &NodeIdChirho {
        &self.node_id_chirho
    }

    pub fn process_generation_chirho(&self) -> u64 {
        self.process_generation_chirho
    }

    /// The Raft term published with the generation held for this handoff.
    pub fn published_raft_term_chirho(&self) -> u64 {
        self.published_raft_term_chirho
    }

    /// Release the exact marker while the generation mutex is still retained.
    ///
    /// The caller must durably commit the terminal decision before consuming this guard.
    pub fn release_chirho(mut self) {
        self._state_guard_chirho.active_handoff_digest_chirho = None;
        self._state_guard_chirho.active_handoff_generation_chirho = None;
    }
}

/// Snapshot-only witness for reads admitted while one exact handoff remains active.
///
/// `handoff_activation_generation_chirho` is scoped to this live authority instance. Its numeric
/// value resets after reconstruction or process restart and must never be compared across handles
/// from different live instances. A migration witness retains the exact handle and refuses once its
/// elector is dropped; the numeric value alone carries no cross-instance authority.
pub struct LocalAppendHandoffReadGenerationChirho {
    handoff_digest_chirho: String,
    consistency_group_chirho: ConsistencyGroupIdChirho,
    node_id_chirho: NodeIdChirho,
    process_generation_chirho: u64,
    published_raft_term_chirho: u64,
    handoff_activation_generation_chirho: u64,
}

impl LocalAppendHandoffReadGenerationChirho {
    pub fn handoff_digest_chirho(&self) -> &str {
        &self.handoff_digest_chirho
    }

    pub fn consistency_group_chirho(&self) -> &ConsistencyGroupIdChirho {
        &self.consistency_group_chirho
    }

    pub fn node_id_chirho(&self) -> &NodeIdChirho {
        &self.node_id_chirho
    }

    pub fn process_generation_chirho(&self) -> u64 {
        self.process_generation_chirho
    }

    /// The Raft term published with this read generation.
    pub fn published_raft_term_chirho(&self) -> u64 {
        self.published_raft_term_chirho
    }

    /// The activation lifetime of the marker within this exact live authority instance.
    pub fn handoff_activation_generation_chirho(&self) -> u64 {
        self.handoff_activation_generation_chirho
    }
}

/// The publisher half retained exclusively by the owning elector.
pub(crate) struct LocalAppendAuthorityPublisherChirho {
    shared_chirho: Arc<LocalAppendAuthoritySharedChirho>,
}

impl LocalAppendAuthorityPublisherChirho {
    /// Announce a transition before waiting for any held append guard, then invalidate the publication.
    pub(crate) fn begin_transition_chirho(&self) -> LocalAppendAuthorityTransitionChirho<'_> {
        begin_transition_chirho(&self.shared_chirho)
    }
}

fn begin_transition_chirho(
    shared_chirho: &Arc<LocalAppendAuthoritySharedChirho>,
) -> LocalAppendAuthorityTransitionChirho<'_> {
    shared_chirho
        .transition_pending_chirho
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending_chirho| {
            pending_chirho.checked_add(1)
        })
        .expect("local append-authority transition-pending counter overflow");

    let mut state_guard_chirho = shared_chirho
        .state_chirho
        .lock()
        .unwrap_or_else(|poisoned_chirho| poisoned_chirho.into_inner());
    state_guard_chirho.published_observation_chirho = None;
    LocalAppendAuthorityTransitionChirho {
        shared_chirho,
        state_guard_chirho: Some(state_guard_chirho),
    }
}

impl Drop for LocalAppendAuthorityPublisherChirho {
    fn drop(&mut self) {
        // A cloned handle may have a live guard on this same thread. Waiting for that guard here would
        // self-deadlock during elector destruction. The alive bit makes teardown O(1): an already-issued
        // guard may finish, while every later acquisition through a stale handle refuses.
        self.shared_chirho
            .elector_alive_chirho
            .store(false, Ordering::Release);
    }
}

/// Construct the sealed publisher/handle pair for one elector instance.
pub(crate) fn local_append_authority_pair_chirho(
    consistency_group_chirho: ConsistencyGroupIdChirho,
    node_id_chirho: NodeIdChirho,
) -> (
    LocalAppendAuthorityPublisherChirho,
    LocalAppendAuthorityHandleChirho,
) {
    local_append_authority_pair_with_optional_monotonic_lease_chirho(
        consistency_group_chirho,
        node_id_chirho,
        None,
    )
}

pub(crate) fn local_append_authority_pair_with_monotonic_lease_chirho(
    consistency_group_chirho: ConsistencyGroupIdChirho,
    node_id_chirho: NodeIdChirho,
    clock_chirho: Arc<dyn MonotonicClockChirho>,
    expiry_millis_chirho: u64,
) -> (
    LocalAppendAuthorityPublisherChirho,
    LocalAppendAuthorityHandleChirho,
) {
    local_append_authority_pair_with_optional_monotonic_lease_chirho(
        consistency_group_chirho,
        node_id_chirho,
        Some(LocalAppendAuthorityMonotonicLeaseChirho {
            clock_chirho,
            expiry_millis_chirho,
        }),
    )
}

fn local_append_authority_pair_with_optional_monotonic_lease_chirho(
    consistency_group_chirho: ConsistencyGroupIdChirho,
    node_id_chirho: NodeIdChirho,
    monotonic_lease_chirho: Option<LocalAppendAuthorityMonotonicLeaseChirho>,
) -> (
    LocalAppendAuthorityPublisherChirho,
    LocalAppendAuthorityHandleChirho,
) {
    let shared_chirho = Arc::new(LocalAppendAuthoritySharedChirho {
        elector_alive_chirho: AtomicBool::new(true),
        terminal_failure_chirho: AtomicBool::new(false),
        transition_pending_chirho: AtomicUsize::new(0),
        consistency_group_chirho,
        node_id_chirho,
        monotonic_lease_chirho,
        state_chirho: Mutex::new(LocalAppendAuthorityStateChirho {
            process_generation_chirho: 0,
            last_observation_chirho: None,
            published_observation_chirho: None,
            active_handoff_digest_chirho: None,
            handoff_activation_generation_counter_chirho: 0,
            active_handoff_generation_chirho: None,
        }),
    });
    (
        LocalAppendAuthorityPublisherChirho {
            shared_chirho: Arc::clone(&shared_chirho),
        },
        LocalAppendAuthorityHandleChirho { shared_chirho },
    )
}

/// A transition owns the gate while `RawNode` mutates and durable Raft writes complete.
pub(crate) struct LocalAppendAuthorityTransitionChirho<'a> {
    shared_chirho: &'a LocalAppendAuthoritySharedChirho,
    state_guard_chirho: Option<MutexGuard<'a, LocalAppendAuthorityStateChirho>>,
}

impl LocalAppendAuthorityTransitionChirho<'_> {
    /// Publish one fixed-field observation after the entire transition succeeds.
    pub(crate) fn publish_chirho(
        mut self,
        observation_chirho: LocalAppendAuthorityObservationChirho,
    ) {
        if self
            .shared_chirho
            .terminal_failure_chirho
            .load(Ordering::Acquire)
        {
            return;
        }
        let state_guard_chirho = self
            .state_guard_chirho
            .as_mut()
            .expect("local append-authority transition guard exists");
        if !state_guard_chirho
            .last_observation_chirho
            .is_some_and(|prior_chirho| prior_chirho.same_authority_view_chirho(observation_chirho))
        {
            state_guard_chirho.process_generation_chirho = state_guard_chirho
                .process_generation_chirho
                .checked_add(1)
                .expect("local append-authority process generation overflow");
            state_guard_chirho.last_observation_chirho = Some(observation_chirho);
        }
        state_guard_chirho.published_observation_chirho = Some(observation_chirho);
    }

    /// Permanently close append admission after any transition error with uncertain mutation state.
    pub(crate) fn fail_terminal_chirho(mut self) {
        self.shared_chirho
            .terminal_failure_chirho
            .store(true, Ordering::Release);
        if let Some(state_guard_chirho) = self.state_guard_chirho.as_mut() {
            state_guard_chirho.published_observation_chirho = None;
        }
    }
}

impl Drop for LocalAppendAuthorityTransitionChirho<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.shared_chirho
                .terminal_failure_chirho
                .store(true, Ordering::Release);
        }
        drop(self.state_guard_chirho.take());
        let previous_chirho = self
            .shared_chirho
            .transition_pending_chirho
            .fetch_sub(1, Ordering::Release);
        debug_assert!(previous_chirho > 0);
    }
}

struct LocalAppendAuthoritySharedChirho {
    elector_alive_chirho: AtomicBool,
    terminal_failure_chirho: AtomicBool,
    transition_pending_chirho: AtomicUsize,
    consistency_group_chirho: ConsistencyGroupIdChirho,
    node_id_chirho: NodeIdChirho,
    monotonic_lease_chirho: Option<LocalAppendAuthorityMonotonicLeaseChirho>,
    state_chirho: Mutex<LocalAppendAuthorityStateChirho>,
}

struct LocalAppendAuthorityMonotonicLeaseChirho {
    clock_chirho: Arc<dyn MonotonicClockChirho>,
    expiry_millis_chirho: u64,
}

struct LocalAppendAuthorityStateChirho {
    process_generation_chirho: u64,
    last_observation_chirho: Option<LocalAppendAuthorityObservationChirho>,
    published_observation_chirho: Option<LocalAppendAuthorityObservationChirho>,
    active_handoff_digest_chirho: Option<String>,
    /// Monotonic only for this live authority instance; it resets on reconstruction/restart.
    handoff_activation_generation_counter_chirho: u64,
    active_handoff_generation_chirho: Option<u64>,
}

fn reserve_handoff_activation_generation_chirho(
    state_chirho: &mut LocalAppendAuthorityStateChirho,
) -> Result<u64, LocalAppendAuthorityRefusalChirho> {
    let next_generation_chirho = state_chirho
        .handoff_activation_generation_counter_chirho
        .checked_add(1)
        .ok_or(LocalAppendAuthorityRefusalChirho::HandoffGenerationExhaustedChirho)?;
    state_chirho.handoff_activation_generation_counter_chirho = next_generation_chirho;
    Ok(next_generation_chirho)
}

impl LocalAppendAuthorityObservationChirho {
    fn same_authority_view_chirho(self, other_chirho: Self) -> bool {
        // A refreshed confirmation extends the same generation; it must update the published
        // observation without making every healthy tick look like a new authority owner/view.
        self.local_is_leader_chirho == other_chirho.local_is_leader_chirho
            && self.warmup_lease_valid_chirho == other_chirho.warmup_lease_valid_chirho
            && self.local_is_promotable_voter_chirho
                == other_chirho.local_is_promotable_voter_chirho
            && self.transfer_in_progress_chirho == other_chirho.transfer_in_progress_chirho
            && self.published_raft_term_chirho == other_chirho.published_raft_term_chirho
    }
}

fn validate_handoff_digest_chirho(
    handoff_digest_chirho: &str,
) -> Result<(), LocalAppendAuthorityRefusalChirho> {
    if handoff_digest_chirho.len() != 64
        || !handoff_digest_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
    {
        return Err(LocalAppendAuthorityRefusalChirho::InvalidHandoffIdentityChirho);
    }
    Ok(())
}

fn validate_observation_chirho(
    shared_chirho: &LocalAppendAuthoritySharedChirho,
    observation_chirho: LocalAppendAuthorityObservationChirho,
) -> Result<(), LocalAppendAuthorityRefusalChirho> {
    if !observation_chirho.local_is_leader_chirho {
        return Err(LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho);
    }
    if !observation_chirho.warmup_lease_valid_chirho {
        return Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho);
    }
    if let Some(lease_chirho) = &shared_chirho.monotonic_lease_chirho {
        let now_chirho = lease_chirho.clock_chirho.now_millis_chirho();
        let confirmation_is_live_chirho = observation_chirho.lease_confirmed_millis_chirho != 0
            && now_chirho
                .checked_sub(observation_chirho.lease_confirmed_millis_chirho)
                .is_some_and(|elapsed_chirho| elapsed_chirho < lease_chirho.expiry_millis_chirho);
        if !confirmation_is_live_chirho {
            return Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho);
        }
    }
    if !observation_chirho.local_is_promotable_voter_chirho {
        return Err(LocalAppendAuthorityRefusalChirho::NotPromotableVoterChirho);
    }
    if observation_chirho.transfer_in_progress_chirho {
        return Err(LocalAppendAuthorityRefusalChirho::LeadershipTransferInProgressChirho);
    }
    if observation_chirho.published_raft_term_chirho == 0
        || observation_chirho.published_raft_term_chirho > u32::MAX as u64
    {
        return Err(LocalAppendAuthorityRefusalChirho::PublishedRaftTermOutOfRangeChirho);
    }
    Ok(())
}
