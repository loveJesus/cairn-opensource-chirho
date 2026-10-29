// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Prepaid test-credit budget for provisioning: reserve a maximum, then settle or release — never both.
//!
//! CF8 clause 11. Provisioning costs money before it is known to have worked, which is the shape that
//! leaks: charge first and the failure path owes a refund; charge after and a crash between provision
//! and charge is free infrastructure. So a **reservation** is taken against a prepaid ceiling BEFORE
//! anything is provisioned, and it later resolves exactly once — settled for what was actually used,
//! or released in full.
//!
//! **Conservation is the invariant, and it is checked rather than argued** — but state it as what is
//! ENFORCED, because an earlier version of this sentence said `reserved == settled + released` and
//! that is FALSE for a partial settle (measured 2026-08-23: reserved 30000, settled 12000, released
//! 0). What holds, per `conservation_holds_chirho`:
//!
//! * a settlement never exceeds its reservation (`settled <= reserved`) — spending credits nobody set
//!   aside is precisely what the ceiling exists to prevent;
//! * a release returns the reservation in FULL (`released == reserved`);
//! * an unresolved reservation has no terminal outcome yet, so terminal conservation does not apply;
//! * **a partial settle implicitly returns the remainder, and that remainder is never recorded as a
//!   release** — `available = ceiling - settled - outstanding` accounts for it because the whole
//!   reservation leaves `outstanding` on resolution.
//!
//! **Do not "fix" this into `reserved == settled + released`.** A verifier written from the old
//! sentence refuses honest logs on every partial settle — the same shape as a replay-side contiguity
//! check over a lawfully gapped sequence, which is a real trap already guarded one crate over.
//!
//! **Terminal resolution is IDEMPOTENT because restart recovery will retry it.** A recovering node
//! cannot know whether its release landed, so it re-drives the terminal step; re-driving must be a
//! no-op returning the same outcome rather than a second release. That is the difference between
//! recovery and double-spending, and it is why `settle` and `release` return the existing outcome for
//! an already-resolved reservation instead of erroring — an error would tempt a caller to retry
//! differently.
//!
//! **A deadline releases, it does not settle.** If a provision neither succeeded nor failed by its
//! durable deadline, the safe resolution is the full release: unproven work is not billable, and
//! erring the other way charges for infrastructure that may not exist.
//!
//! Pure: no clock, no I/O. "Now" arrives as a parameter so deadline behaviour is testable exactly.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How a reservation ended. Terminal and mutually exclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetOutcomeChirho {
    /// Provision succeeded; this many credits were consumed and the remainder released.
    SettledChirho { settled_micros_chirho: u64 },
    /// Provision failed or passed its deadline; the whole reservation returned to the budget.
    ReleasedChirho { released_micros_chirho: u64 },
}

/// Why a budget operation is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetRefusalChirho {
    /// The reservation would exceed the prepaid ceiling. Admission stops here, before provisioning.
    ExceedsPrepaidCeilingChirho {
        requested_micros_chirho: u64,
        available_micros_chirho: u64,
    },
    /// Settling for more than was reserved would spend credits nobody set aside.
    SettlementExceedsReservationChirho {
        reserved_micros_chirho: u64,
        settle_micros_chirho: u64,
    },
    /// No such reservation — a resolution for something never reserved is not idempotency, it is a bug.
    UnknownReservationChirho { reservation_id_chirho: String },
    /// A reservation of zero reserves nothing and would resolve to nothing.
    ZeroReservationChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ReservationChirho {
    reserved_micros_chirho: u64,
    deadline_millis_chirho: u64,
    outcome_chirho: Option<BudgetOutcomeChirho>,
}

/// A prepaid test-credit budget with its outstanding and resolved reservations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfrastructureBudgetChirho {
    prepaid_ceiling_micros_chirho: u64,
    reservations_chirho: BTreeMap<String, ReservationChirho>,
}

impl InfrastructureBudgetChirho {
    pub fn new_chirho(prepaid_ceiling_micros_chirho: u64) -> Self {
        Self {
            prepaid_ceiling_micros_chirho,
            reservations_chirho: BTreeMap::new(),
        }
    }

    /// Credits currently held by unresolved reservations.
    pub fn outstanding_micros_chirho(&self) -> u64 {
        self.reservations_chirho
            .values()
            .filter(|reservation_chirho| reservation_chirho.outcome_chirho.is_none())
            .map(|reservation_chirho| reservation_chirho.reserved_micros_chirho)
            .fold(0_u64, u64::saturating_add)
    }

    /// Credits actually consumed by settled reservations.
    pub fn settled_micros_chirho(&self) -> u64 {
        self.reservations_chirho
            .values()
            .filter_map(
                |reservation_chirho| match reservation_chirho.outcome_chirho {
                    Some(BudgetOutcomeChirho::SettledChirho {
                        settled_micros_chirho,
                    }) => Some(settled_micros_chirho),
                    _ => None,
                },
            )
            .fold(0_u64, u64::saturating_add)
    }

    /// What a further reservation may still claim: the ceiling less what is spent or held.
    pub fn available_micros_chirho(&self) -> u64 {
        self.prepaid_ceiling_micros_chirho
            .saturating_sub(self.settled_micros_chirho())
            .saturating_sub(self.outstanding_micros_chirho())
    }

    /// Reserve a priced maximum BEFORE provisioning. Refused past the ceiling — which is admission
    /// control, not accounting: the refusal happens while nothing has been built yet.
    pub fn reserve_chirho(
        &mut self,
        reservation_id_chirho: &str,
        requested_micros_chirho: u64,
        deadline_millis_chirho: u64,
    ) -> Result<(), BudgetRefusalChirho> {
        if requested_micros_chirho == 0 {
            return Err(BudgetRefusalChirho::ZeroReservationChirho);
        }
        // An existing id re-reserving is idempotent for the same reason resolution is: a retrying
        // caller must not stack a second hold on the same intent.
        if self.reservations_chirho.contains_key(reservation_id_chirho) {
            return Ok(());
        }
        let available_chirho = self.available_micros_chirho();
        if requested_micros_chirho > available_chirho {
            return Err(BudgetRefusalChirho::ExceedsPrepaidCeilingChirho {
                requested_micros_chirho,
                available_micros_chirho: available_chirho,
            });
        }
        self.reservations_chirho.insert(
            reservation_id_chirho.to_string(),
            ReservationChirho {
                reserved_micros_chirho: requested_micros_chirho,
                deadline_millis_chirho,
                outcome_chirho: None,
            },
        );
        Ok(())
    }

    /// Settle a reservation for what was actually used. Idempotent: an already-resolved reservation
    /// returns its existing outcome unchanged, because restart recovery WILL call this again.
    pub fn settle_chirho(
        &mut self,
        reservation_id_chirho: &str,
        settle_micros_chirho: u64,
    ) -> Result<BudgetOutcomeChirho, BudgetRefusalChirho> {
        let reservation_chirho = self
            .reservations_chirho
            .get_mut(reservation_id_chirho)
            .ok_or_else(|| BudgetRefusalChirho::UnknownReservationChirho {
                reservation_id_chirho: reservation_id_chirho.to_string(),
            })?;
        if let Some(existing_chirho) = reservation_chirho.outcome_chirho {
            return Ok(existing_chirho);
        }
        if settle_micros_chirho > reservation_chirho.reserved_micros_chirho {
            return Err(BudgetRefusalChirho::SettlementExceedsReservationChirho {
                reserved_micros_chirho: reservation_chirho.reserved_micros_chirho,
                settle_micros_chirho,
            });
        }
        let outcome_chirho = BudgetOutcomeChirho::SettledChirho {
            settled_micros_chirho: settle_micros_chirho,
        };
        reservation_chirho.outcome_chirho = Some(outcome_chirho);
        Ok(outcome_chirho)
    }

    /// Release a reservation in full — the compensating resolution for a failed provision.
    ///
    /// **Its idempotency guard is defensive-by-symmetry, NOT independently provable, and that is
    /// stated because a mutation proved it.** Removing this guard breaks no test: re-releasing writes
    /// the SAME terminal outcome, which is indistinguishable from writing it once, so no observable
    /// state differs. The guard that genuinely bears weight is `settle_chirho`'s — without it a late
    /// settle overwrites a release and converts a refund into a charge, which a test does catch.
    /// Keep this one anyway: it makes the two paths behave alike, and a future outcome carrying a
    /// timestamp or sequence would make re-writing observable. It is simply not proven today, and
    /// saying so is better than implying a mutation confirmed it.
    pub fn release_chirho(
        &mut self,
        reservation_id_chirho: &str,
    ) -> Result<BudgetOutcomeChirho, BudgetRefusalChirho> {
        let reservation_chirho = self
            .reservations_chirho
            .get_mut(reservation_id_chirho)
            .ok_or_else(|| BudgetRefusalChirho::UnknownReservationChirho {
                reservation_id_chirho: reservation_id_chirho.to_string(),
            })?;
        if let Some(existing_chirho) = reservation_chirho.outcome_chirho {
            return Ok(existing_chirho);
        }
        let outcome_chirho = BudgetOutcomeChirho::ReleasedChirho {
            released_micros_chirho: reservation_chirho.reserved_micros_chirho,
        };
        reservation_chirho.outcome_chirho = Some(outcome_chirho);
        Ok(outcome_chirho)
    }

    /// Drive every unresolved reservation whose deadline has passed to a RELEASE.
    ///
    /// Deliberately releases rather than settles: work that never proved it succeeded is not
    /// billable, and the opposite default charges for infrastructure that may not exist. Returns the
    /// ids it resolved, and is safe to call repeatedly — which restart recovery does.
    pub fn release_expired_chirho(&mut self, now_millis_chirho: u64) -> Vec<String> {
        let expired_chirho: Vec<String> = self
            .reservations_chirho
            .iter()
            .filter(|(_, reservation_chirho)| {
                reservation_chirho.outcome_chirho.is_none()
                    && reservation_chirho.deadline_millis_chirho <= now_millis_chirho
            })
            .map(|(id_chirho, _)| id_chirho.clone())
            .collect();
        for id_chirho in &expired_chirho {
            let _ = self.release_chirho(id_chirho);
        }
        expired_chirho
    }

    /// **Conservation bounds:** unresolved reservations have no terminal bound yet; no settlement
    /// exceeds its reservation; and a release returns its reservation in full. Partial-settlement
    /// remainder is accounted for by the availability formula, not this predicate or a synthetic
    /// release event.
    pub fn conservation_holds_chirho(&self) -> bool {
        self.reservations_chirho.values().all(|reservation_chirho| {
            match reservation_chirho.outcome_chirho {
                None => true,
                Some(BudgetOutcomeChirho::SettledChirho {
                    settled_micros_chirho,
                }) => settled_micros_chirho <= reservation_chirho.reserved_micros_chirho,
                Some(BudgetOutcomeChirho::ReleasedChirho {
                    released_micros_chirho,
                }) => released_micros_chirho == reservation_chirho.reserved_micros_chirho,
            }
        })
    }
}

#[cfg(test)]
#[path = "infrastructure_budget_tests_chirho.rs"]
mod infrastructure_budget_tests_chirho;
