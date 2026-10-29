// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The served sign-in gate: it carries the principal's limit to the durable pre-check, and keeps two process-local limits
//! per network source: successful sign-ins per hour (brick 4a), and recorded FAILED attempts per failure window across
//! login, token and recover (R12).
//!
//! - **The source** is the served abuse gate's own network actor: the peer, with X-Forwarded-For trusted only behind a
//!   loopback proxy, as a keyed hash. Both gates agree on what a source is, and no IP reaches a durable log (the
//!   bounded-auth charter's gate names this actor as the candidate).
//! - **What each limit charges.** The success limit charges only a confirmed success. The failure limit (R12, PFE
//!   #26065, sized #26068) charges only an attempt whose road RECORDED a failed attempt row: never a parse, floor,
//!   policy or rate refusal, and never a success. One failure budget covers login, token and recover, so rotating
//!   doors or invented principals does not multiply it.
//! - **Both are checked BEFORE any credential work and any append,** and refuse with the error type every sign-in
//!   rate refusal uses, so the response is identical whichever limit fired, and for a right or a wrong password
//!   (PFE #25922, agy #25924). A refusal at either limit charges nothing.
//! - **The authoritative check is an admission inside the blocking task** (`SignInMeterChirho`, run by
//!   `run_blocking_public_auth_chirho`), right before the work. Under the gate's locks it counts the source's charges
//!   AND the slots other admitted attempts hold, refuses at either limit, and otherwise reserves this attempt's slots.
//!   After the work, in the same task, the attempt settles: a success keeps its success slot, a recorded failure its
//!   failure slot, and the rest are released. A task that panics after its admission never settles: both its slots stay
//!   charged until they leave their windows, the conservative error (PFE #26814).
//!   - So a burst queued behind the permit, which all passed the handler's early check, cannot overrun a limit, at any
//!     permit count (R12; PFE #26081, item 4).
//!   - A client that hangs up mid-request cannot skip the settling: the server drops its handler, but the task runs on.
//!   - An attempt in flight holds both slots until it settles, so a source at a limit's edge may be refused up to one
//!     attempt per permit early, never late.
//! - **At the bucket cap the least recently charged bucket is evicted, never a refusal:** refusing would let anyone
//!   with enough addresses lock every new source out of signing in. Rotating addresses can create failure buckets; the
//!   cap bounds them.
//! - **IPv4 today, and IPv6 is already keyed by its /64.** perffection.com has no AAAA record, so a source is the
//!   client's real IPv4 (PFE #26068). The served actor key zeroes an IPv6 address's low 64 bits
//!   (`normalized_ip_bytes_chirho`), so one host holding a whole /64 is one source. The residual: a /48 holds 65,536
//!   /64s, more than the bucket cap, so an attacker with one outruns eviction, as an IPv4 botnet larger than the cap
//!   does.
//! - **Process-local:** a restart forgets it. The principal's limit is durable, from the auth-attempt log.
//!
//! Workflow: the sign-in check DAG in `spec-chirho/workflows-chirho/identity-auth-chirho/bounded-auth-history-chirho.md`.

use super::served_request_abuse_gate_chirho::{
    served_network_actor_key_chirho, ServedRequestActorKeyChirho,
};
use super::served_request_limits_chirho::ServedRequestAbuseLimitsChirho;
use anyhow::Result;
use axum::http::HeaderMap;
use cairn_chirho::identity_chirho;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

pub(super) struct SignInGateChirho {
    velocity_chirho: identity_chirho::SignInVelocityChirho,
    source_max_chirho: u64,
    failure_max_chirho: u64,
    bucket_cap_chirho: usize,
    started_chirho: Instant,
    /// Each source's successful sign-ins, in charge order, as milliseconds since `started_chirho`; an admitted
    /// attempt's success slot sits here as a reservation until it settles.
    buckets_chirho: Mutex<HashMap<ServedRequestActorKeyChirho, VecDeque<u64>>>,
    /// Each source's recorded FAILED attempts across login, token and recover (R12), the same way, with reservations.
    /// Whoever holds both locks takes `buckets_chirho` first.
    failure_buckets_chirho: Mutex<HashMap<ServedRequestActorKeyChirho, VecDeque<u64>>>,
}

/// A source that passed the handler's check; the handler turns it into a meter for its blocking task.
pub(super) struct SignInSourceChirho(ServedRequestActorKeyChirho);

/// Which budgets a road's admission reserves. Every road reserves a failure slot; login and token also reserve a
/// success slot, and recover never does (PFE ruling (a): a setup creates no session).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SignInChargesChirho {
    SuccessesAndFailuresChirho,
    FailuresOnlyChirho,
}

/// One attempt's metering, handed from the handler into its blocking task (R12): the gate, the checked source, the
/// road and its charges.
pub(super) struct SignInMeterChirho {
    gate_chirho: Arc<SignInGateChirho>,
    key_chirho: ServedRequestActorKeyChirho,
    endpoint_chirho: &'static str,
    charges_chirho: SignInChargesChirho,
}

/// The slots one admitted attempt holds until it settles.
pub(super) struct SignInAdmissionChirho {
    at_ms_chirho: u64,
    success_reserved_chirho: bool,
}

impl SignInMeterChirho {
    /// The authoritative check, in the blocking task right before the work: refuse when either budget is full,
    /// counting the slots other admitted attempts hold; otherwise reserve this attempt's slots, atomically under the
    /// gate's locks. A burst queued behind the permit therefore cannot overrun a limit, however many permits run.
    pub(super) fn admit_chirho(&self) -> Result<SignInAdmissionChirho> {
        self.gate_chirho.admit_at_chirho(
            self.key_chirho,
            self.endpoint_chirho,
            self.charges_chirho,
            self.gate_chirho.now_ms_chirho(),
        )
    }

    /// After the work, in the same task: a success keeps its success slot, a refusal that recorded a failed row keeps
    /// its failure slot, and every other slot is released.
    pub(super) fn settle_chirho<OutputChirho>(
        &self,
        admission_chirho: SignInAdmissionChirho,
        outcome_chirho: &std::result::Result<
            OutputChirho,
            identity_chirho::PublicAuthRefusalChirho,
        >,
    ) {
        let succeeded_chirho = outcome_chirho.is_ok();
        let failure_recorded_chirho = outcome_chirho
            .as_ref()
            .is_err_and(|refusal_chirho| refusal_chirho.failure_recorded_chirho);
        self.gate_chirho.settle_chirho(
            self.key_chirho,
            admission_chirho,
            succeeded_chirho,
            failure_recorded_chirho,
        );
    }
}

impl SignInGateChirho {
    pub(super) fn new_chirho(limits_chirho: &ServedRequestAbuseLimitsChirho) -> Self {
        Self {
            velocity_chirho: identity_chirho::SignInVelocityChirho {
                principal_successes_per_hour_chirho: limits_chirho
                    .sign_in_principal_successes_per_hour_chirho,
            },
            source_max_chirho: limits_chirho.sign_in_source_successes_per_hour_chirho,
            failure_max_chirho: limits_chirho.sign_in_source_failures_per_window_chirho,
            bucket_cap_chirho: limits_chirho.actor_bucket_cap_chirho,
            started_chirho: Instant::now(),
            buckets_chirho: Mutex::new(HashMap::new()),
            failure_buckets_chirho: Mutex::new(HashMap::new()),
        }
    }

    /// The principal's limit, for the durable pre-check inside the sign-in.
    pub(super) fn velocity_chirho(&self) -> identity_chirho::SignInVelocityChirho {
        self.velocity_chirho
    }

    /// The handler's early refusal, before any work: a source already at either limit (reservations included) is
    /// refused at once. It reserves nothing; the authoritative check is the meter's admission, in the task.
    pub(super) fn check_source_chirho(
        &self,
        peer_chirho: Option<SocketAddr>,
        headers_chirho: &HeaderMap,
        endpoint_chirho: &str,
    ) -> Result<SignInSourceChirho> {
        let key_chirho = served_network_actor_key_chirho(peer_chirho, headers_chirho);
        let now_ms_chirho = self.now_ms_chirho();
        let mut successes_chirho = self
            .buckets_chirho
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut failures_chirho = self
            .failure_buckets_chirho
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.refusal_at_chirho(
            &mut successes_chirho,
            &mut failures_chirho,
            &key_chirho,
            endpoint_chirho,
            now_ms_chirho,
        )?;
        Ok(SignInSourceChirho(key_chirho))
    }

    /// The meter for one attempt from a checked source, for its blocking task.
    pub(super) fn meter_chirho(
        self: &Arc<Self>,
        source_chirho: SignInSourceChirho,
        endpoint_chirho: &'static str,
        charges_chirho: SignInChargesChirho,
    ) -> SignInMeterChirho {
        SignInMeterChirho {
            gate_chirho: Arc::clone(self),
            key_chirho: source_chirho.0,
            endpoint_chirho,
            charges_chirho,
        }
    }

    /// Either limit's refusal for a source at `now_ms_chirho`, on maps the caller holds locked: the success budget
    /// over the hour, then R12's failure budget over its window, ONE budget across login, token and recover, so
    /// rotating invented principals or doors does not multiply it.
    fn refusal_at_chirho(
        &self,
        successes_chirho: &mut HashMap<ServedRequestActorKeyChirho, VecDeque<u64>>,
        failures_chirho: &mut HashMap<ServedRequestActorKeyChirho, VecDeque<u64>>,
        key_chirho: &ServedRequestActorKeyChirho,
        endpoint_chirho: &str,
        now_ms_chirho: u64,
    ) -> Result<()> {
        let refusal_chirho = |window_ms_chirho, max_chirho, reason_chirho| {
            identity_chirho::AuthRateLimitExceededChirho {
                principal_hash_chirho: String::new(),
                endpoint_chirho: endpoint_chirho.to_string(),
                window_ms_chirho,
                max_failures_chirho: max_chirho,
                reason_chirho,
            }
        };
        if recent_locked_chirho(
            successes_chirho,
            key_chirho,
            identity_chirho::SIGN_IN_SUCCESS_WINDOW_MS_CHIRHO,
            now_ms_chirho,
        ) >= self.source_max_chirho
        {
            return Err(refusal_chirho(
                identity_chirho::SIGN_IN_SUCCESS_WINDOW_MS_CHIRHO,
                self.source_max_chirho,
                identity_chirho::AuthRateLimitReasonChirho::SourceSignInsChirho,
            )
            .into());
        }
        if recent_locked_chirho(
            failures_chirho,
            key_chirho,
            identity_chirho::PUBLIC_AUTH_FAILURE_WINDOW_MS_CHIRHO,
            now_ms_chirho,
        ) >= self.failure_max_chirho
        {
            return Err(refusal_chirho(
                identity_chirho::PUBLIC_AUTH_FAILURE_WINDOW_MS_CHIRHO,
                self.failure_max_chirho,
                identity_chirho::AuthRateLimitReasonChirho::SourceFailuresChirho,
            )
            .into());
        }
        Ok(())
    }

    /// Check and reserve under both locks, in the documented order, so no other attempt from the source can slip
    /// between the count and the reservation.
    fn admit_at_chirho(
        &self,
        key_chirho: ServedRequestActorKeyChirho,
        endpoint_chirho: &str,
        charges_chirho: SignInChargesChirho,
        now_ms_chirho: u64,
    ) -> Result<SignInAdmissionChirho> {
        let mut successes_chirho = self
            .buckets_chirho
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut failures_chirho = self
            .failure_buckets_chirho
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.refusal_at_chirho(
            &mut successes_chirho,
            &mut failures_chirho,
            &key_chirho,
            endpoint_chirho,
            now_ms_chirho,
        )?;
        let success_reserved_chirho =
            charges_chirho == SignInChargesChirho::SuccessesAndFailuresChirho;
        if success_reserved_chirho {
            push_locked_chirho(
                &mut successes_chirho,
                key_chirho,
                now_ms_chirho,
                identity_chirho::SIGN_IN_SUCCESS_WINDOW_MS_CHIRHO,
                self.bucket_cap_chirho,
            );
        }
        push_locked_chirho(
            &mut failures_chirho,
            key_chirho,
            now_ms_chirho,
            identity_chirho::PUBLIC_AUTH_FAILURE_WINDOW_MS_CHIRHO,
            self.bucket_cap_chirho,
        );
        Ok(SignInAdmissionChirho {
            at_ms_chirho: now_ms_chirho,
            success_reserved_chirho,
        })
    }

    /// Keep the slot the outcome earned and release the rest. A reservation eviction already dropped is simply gone.
    fn settle_chirho(
        &self,
        key_chirho: ServedRequestActorKeyChirho,
        admission_chirho: SignInAdmissionChirho,
        succeeded_chirho: bool,
        failure_recorded_chirho: bool,
    ) {
        if admission_chirho.success_reserved_chirho && !succeeded_chirho {
            release_chirho(
                &self.buckets_chirho,
                &key_chirho,
                admission_chirho.at_ms_chirho,
            );
        }
        if !failure_recorded_chirho {
            release_chirho(
                &self.failure_buckets_chirho,
                &key_chirho,
                admission_chirho.at_ms_chirho,
            );
        }
    }

    /// The handler's check at a given time, for the unit arms.
    #[cfg(test)]
    fn check_source_at_chirho(
        &self,
        peer_chirho: Option<SocketAddr>,
        headers_chirho: &HeaderMap,
        endpoint_chirho: &str,
        now_ms_chirho: u64,
    ) -> Result<SignInSourceChirho> {
        let key_chirho = served_network_actor_key_chirho(peer_chirho, headers_chirho);
        let mut successes_chirho = self
            .buckets_chirho
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut failures_chirho = self
            .failure_buckets_chirho
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.refusal_at_chirho(
            &mut successes_chirho,
            &mut failures_chirho,
            &key_chirho,
            endpoint_chirho,
            now_ms_chirho,
        )?;
        Ok(SignInSourceChirho(key_chirho))
    }

    /// A settled success at a given time, for the unit arms.
    #[cfg(test)]
    fn record_success_at_chirho(&self, source_chirho: SignInSourceChirho, now_ms_chirho: u64) {
        let mut successes_chirho = self
            .buckets_chirho
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        push_locked_chirho(
            &mut successes_chirho,
            source_chirho.0,
            now_ms_chirho,
            identity_chirho::SIGN_IN_SUCCESS_WINDOW_MS_CHIRHO,
            self.bucket_cap_chirho,
        );
    }

    /// A settled recorded failure at a given time, for the unit arms.
    #[cfg(test)]
    fn record_failure_at_chirho(&self, source_chirho: SignInSourceChirho, now_ms_chirho: u64) {
        let mut failures_chirho = self
            .failure_buckets_chirho
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        push_locked_chirho(
            &mut failures_chirho,
            source_chirho.0,
            now_ms_chirho,
            identity_chirho::PUBLIC_AUTH_FAILURE_WINDOW_MS_CHIRHO,
            self.bucket_cap_chirho,
        );
    }

    fn now_ms_chirho(&self) -> u64 {
        u64::try_from(self.started_chirho.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// A source's charges and reservations still inside the window ending at `now_ms_chirho`, dropping the expired ones
/// as it reads.
fn recent_locked_chirho(
    buckets_chirho: &mut HashMap<ServedRequestActorKeyChirho, VecDeque<u64>>,
    key_chirho: &ServedRequestActorKeyChirho,
    window_ms_chirho: u64,
    now_ms_chirho: u64,
) -> u64 {
    let window_start_chirho = now_ms_chirho.saturating_sub(window_ms_chirho);
    buckets_chirho
        .get_mut(key_chirho)
        .map_or(0, |bucket_chirho| {
            drop_before_chirho(bucket_chirho, window_start_chirho);
            bucket_chirho.len() as u64
        })
}

/// Push one charge or reservation at `now_ms_chirho`. At the bucket cap, empty buckets go first, then the least
/// recently charged ones: eviction never refuses, since refusing would let anyone with enough addresses lock every new
/// source out.
fn push_locked_chirho(
    buckets_chirho: &mut HashMap<ServedRequestActorKeyChirho, VecDeque<u64>>,
    key_chirho: ServedRequestActorKeyChirho,
    now_ms_chirho: u64,
    window_ms_chirho: u64,
    bucket_cap_chirho: usize,
) {
    buckets_chirho
        .entry(key_chirho)
        .or_default()
        .push_back(now_ms_chirho);
    if buckets_chirho.len() <= bucket_cap_chirho {
        return;
    }
    let window_start_chirho = now_ms_chirho.saturating_sub(window_ms_chirho);
    buckets_chirho.retain(|_, bucket_chirho| {
        drop_before_chirho(bucket_chirho, window_start_chirho);
        !bucket_chirho.is_empty()
    });
    while buckets_chirho.len() > bucket_cap_chirho {
        let Some(oldest_chirho) = buckets_chirho
            .iter()
            .min_by_key(|(_, bucket_chirho)| bucket_chirho.back().copied().unwrap_or(0))
            .map(|(key_chirho, _)| *key_chirho)
        else {
            break;
        };
        buckets_chirho.remove(&oldest_chirho);
    }
}

/// Release one reservation: the newest entry at exactly `at_ms_chirho` in the source's bucket. Entries stay in time
/// order, and an emptied bucket is dropped.
fn release_chirho(
    buckets_chirho: &Mutex<HashMap<ServedRequestActorKeyChirho, VecDeque<u64>>>,
    key_chirho: &ServedRequestActorKeyChirho,
    at_ms_chirho: u64,
) {
    let mut buckets_chirho = buckets_chirho
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(bucket_chirho) = buckets_chirho.get_mut(key_chirho) else {
        return;
    };
    if let Some(position_chirho) = bucket_chirho
        .iter()
        .rposition(|&entry_chirho| entry_chirho == at_ms_chirho)
    {
        bucket_chirho.remove(position_chirho);
    }
    if bucket_chirho.is_empty() {
        buckets_chirho.remove(key_chirho);
    }
}

/// Charges are pushed in time order, so the expired ones are at the front.
fn drop_before_chirho(bucket_chirho: &mut VecDeque<u64>, window_start_chirho: u64) {
    while bucket_chirho
        .front()
        .is_some_and(|&at_ms_chirho| at_ms_chirho < window_start_chirho)
    {
        bucket_chirho.pop_front();
    }
}

#[cfg(test)]
#[path = "sign_in_gate_tests_chirho.rs"]
mod sign_in_gate_tests_chirho;
