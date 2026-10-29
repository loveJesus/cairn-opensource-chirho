// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! An INDEPENDENT second-seat reference for the frozen §11 money core — the ARITHMETIC / CONSERVATION /
//! GRAMMAR oracle, NOT an admission oracle. It re-derives, independently of B: the exhaustive
//! wildcard-free §11.10 op->leg grammar-SHAPE (a new `LedgerOp` fails to compile until classified);
//! the §11.3 checked FOLD; the F4 spendable-floor; and PER-KIND conservation (§11.2 — one unitless
//! sum would accept `Debit A / Credit B` of two kinds, minting one and burning the other). Its REDs
//! adversarially pin all of those against the same failure modes B must refuse.
//!
//! What is DEFERRED (gpt #4486/#4487, claude #4488 — B1): the public accept/reject DIFFERENTIAL of B
//! against this reference. An admitted record can only be trusted as admitted if its "admitted"
//! capability is UNFORGEABLE by a foreign crate. A public marker trait here is forgeable (Rust orphan
//! rules: a downstream crate impls the public trait for a local type, then hands it to the
//! constructor), so admission typing CANNOT be established in this crate. The admitted-record token
//! must be OWNED by `cairn-ledger-log-chirho` (B's crate) with PRIVATE construction — only B's
//! admission path (after membership / mint-burn authority + supply / settlement-role / finality /
//! grammar) constructs one, exposing read-only legs/op. This audit crate will DEPEND ON log (leaf
//! direction; log NEVER depends on audit) and take that token as an input a foreign crate cannot
//! forge. Until B lands it, only the raw arithmetic/grammar checker + its REDs live here; the
//! MoneyFence / differential surface returns typed to B's issued token.
//!
//! Membership (R1), Mint/Burn authority + supply (R2), settlement-role (R3), escrow-control matching,
//! and finality are B's, verified with context/verifiers this reference structurally lacks and pinned
//! by B's OWN authority REDs. The CF2 escrow grammar is independently checked here for exact leg
//! shape and conservation; the real admission path alone proves a control names an unconsumed hold
//! and a Finalize credit targets the registry-selected settlement account. Timer IS supported
//! (§11.10: exactly zero money legs); cross-cluster F3 is fail-closed (no finality verifier). Review:
//! gpt #4442/#4445/#4461/#4462/#4477/#4486/#4487, claude §11.10 / #4488, CF2 revision
//! #4930/#4931.

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

use std::collections::BTreeMap;

pub use cairn_ledger_model_chirho::account_state_chirho::{fold_leg_chirho, AccountStateChirho};
use cairn_ledger_model_chirho::ids_chirho::{AccountIdChirho, AssetKindIdChirho};
use cairn_ledger_model_chirho::record_chirho::{
    LedgerLegChirho, LedgerOpChirho, LegDeltaChirho, LegPostStateChirho,
};

/// Why the reference refused a record's arithmetic/grammar. A real B must refuse the SAME cases on
/// these dimensions (the deferred differential); B has additional ADMISSION rejects the oracle omits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RejectReasonChirho {
    /// Counter overflow/underflow (§11.3 checked-arith, fail-closed).
    ArithmeticChirho,
    /// The op's legs violate the §11.10 op->leg grammar (wrong count/delta/counterpart placement).
    BadOperationShapeChirho,
    /// A `LedgerOp` deliberately unsupported here: bare Credit/Debit (free mint/destruction) or
    /// Compensation. Cross-cluster authority remains B-only after this oracle checks its grammar.
    UnsupportedOperationChirho,
    /// The leg's stored post ≠ fold(true current head, delta) — a stale/forged post (§11.3 fence).
    PostMismatchChirho,
    /// A debit/hold/finalize drove spendable `< 0` (§11.3 F4 spendable-floor).
    OverdraftChirho,
    /// A net-zero op's legs did not net to zero FOR SOME asset kind (§11.2 per-kind conservation).
    NotBalancedChirho,
}

/// How an op is allowed to move total conserved money (§11.2 balance mode).
enum BalanceModeChirho {
    /// Must net to zero PER KIND across legs (Transfer, Timer's zero-leg case).
    NetZeroChirho,
    /// Authorized value entry — money in (Mint). Sign is guaranteed by the 1-Credit shape.
    ValueInChirho,
    /// Authorized value exit — money out (Burn). Sign is guaranteed by the 1-Debit shape.
    ValueOutChirho,
}

/// The reference ledger — in-memory account states. NO storage/journal; the "true current head" IS
/// this map, which is exactly what B's fence reconstructs under its append lock.
#[derive(Clone, Debug, Default)]
pub struct RefLedgerChirho {
    accounts_chirho: BTreeMap<AccountIdChirho, AccountStateChirho>,
}

impl RefLedgerChirho {
    /// A fresh empty ledger (accounts open lazily at their zero baseline — §11.6 genesis biconditional).
    pub fn new_chirho() -> Self {
        Self::default()
    }

    /// Current state of an account (its lazy zero baseline if never touched).
    pub fn state_chirho(&self, account_chirho: &AccountIdChirho) -> AccountStateChirho {
        self.accounts_chirho
            .get(account_chirho)
            .copied()
            .unwrap_or_default()
    }

    /// The exhaustive, wildcard-free §11.10 op->leg grammar-SHAPE (coded independently of B). Every
    /// `LedgerOp` is classified or fails closed; adding a variant fails compilation here until it is
    /// classified. GRAMMAR only — membership/authority/settlement admission is NOT here.
    fn validate_operation_shape_chirho(
        legs_chirho: &[LedgerLegChirho],
        op_chirho: &LedgerOpChirho,
    ) -> Result<BalanceModeChirho, RejectReasonChirho> {
        use BalanceModeChirho::*;
        use LedgerOpChirho::*;
        use LegDeltaChirho as DeltaChirho;
        let has_counterpart_chirho = |ls_chirho: &[LedgerLegChirho]| {
            ls_chirho.iter().any(|l| l.counterpart_chirho.is_some())
        };
        match op_chirho {
            TransferChirho => {
                if has_counterpart_chirho(legs_chirho) {
                    // The F3 boundary form is exactly [Debit settlement, Credit destination], with
                    // exactly one claim on the Credit. Proof/nullifier/role authority stays B-only.
                    if legs_chirho.len() != 2
                        || !matches!(legs_chirho[0].delta_chirho, DeltaChirho::DebitChirho)
                        || legs_chirho[0].counterpart_chirho.is_some()
                        || !matches!(legs_chirho[1].delta_chirho, DeltaChirho::CreditChirho)
                        || legs_chirho[1].counterpart_chirho.is_none()
                    {
                        return Err(RejectReasonChirho::BadOperationShapeChirho);
                    }
                    return Ok(NetZeroChirho);
                }
                if legs_chirho.len() < 2
                    || !legs_chirho.iter().all(|l| {
                        matches!(
                            l.delta_chirho,
                            DeltaChirho::CreditChirho | DeltaChirho::DebitChirho
                        )
                    })
                {
                    return Err(RejectReasonChirho::BadOperationShapeChirho);
                }
                Ok(NetZeroChirho)
            }
            MintChirho { .. } => {
                if legs_chirho.len() != 1
                    || !matches!(legs_chirho[0].delta_chirho, DeltaChirho::CreditChirho)
                    || legs_chirho[0].counterpart_chirho.is_some()
                {
                    return Err(RejectReasonChirho::BadOperationShapeChirho);
                }
                Ok(ValueInChirho)
            }
            BurnChirho { .. } => {
                if legs_chirho.len() != 1
                    || !matches!(legs_chirho[0].delta_chirho, DeltaChirho::DebitChirho)
                    || legs_chirho[0].counterpart_chirho.is_some()
                {
                    return Err(RejectReasonChirho::BadOperationShapeChirho);
                }
                Ok(ValueOutChirho)
            }
            EscrowHoldChirho { .. } => {
                if legs_chirho.len() != 1
                    || !matches!(legs_chirho[0].delta_chirho, DeltaChirho::HoldChirho)
                    || legs_chirho[0].counterpart_chirho.is_some()
                {
                    return Err(RejectReasonChirho::BadOperationShapeChirho);
                }
                Ok(NetZeroChirho)
            }
            EscrowReleaseChirho { .. } => {
                if legs_chirho.len() != 1
                    || !matches!(legs_chirho[0].delta_chirho, DeltaChirho::ReleaseChirho)
                    || legs_chirho[0].counterpart_chirho.is_some()
                {
                    return Err(RejectReasonChirho::BadOperationShapeChirho);
                }
                Ok(NetZeroChirho)
            }
            EscrowFinalizeChirho { .. } => {
                if legs_chirho.len() != 2
                    || !matches!(legs_chirho[0].delta_chirho, DeltaChirho::FinalizeChirho)
                    || !matches!(legs_chirho[1].delta_chirho, DeltaChirho::CreditChirho)
                    || has_counterpart_chirho(legs_chirho)
                {
                    return Err(RejectReasonChirho::BadOperationShapeChirho);
                }
                Ok(NetZeroChirho)
            }
            TimerChirho { .. } => {
                // Supported (§11.10): a timer record carries EXACTLY zero money legs; the durable
                // timer-index/wake behavior is B's actor lifecycle, not the arithmetic oracle.
                if legs_chirho.is_empty() {
                    Ok(NetZeroChirho)
                } else {
                    Err(RejectReasonChirho::BadOperationShapeChirho)
                }
            }
            // ExplicitlyUnsupported (§11.10): bare Credit/Debit grant unbounded value entry/exit;
            // Compensation's inverse shape remains unratified. Both fail closed.
            CreditChirho | DebitChirho | CompensationChirho { .. } => {
                Err(RejectReasonChirho::UnsupportedOperationChirho)
            }
        }
    }

    /// The reference's RAW arithmetic/grammar/conservation checker over a `(legs, op)`: grammar-SHAPE,
    /// then recompute EVERY leg's post from the true current head (reject a post mismatch / overdraft),
    /// then the PER-KIND balance mode; apply atomically only if the whole record passes. This is NOT an
    /// admission gate: it makes NO membership / authority / settlement / finality decision (those are
    /// B's, verified before B ever issues an admitted token), so there is no forgeable admission claim
    /// here (gpt B1). It returns the arithmetic verdict only. The B-vs-reference DIFFERENTIAL that
    /// feeds records through this is DEFERRED until `cairn-ledger-log-chirho` owns the unforgeable
    /// admitted-record token; it will then wrap this checker.
    pub fn apply_grammar_arithmetic_chirho(
        &mut self,
        legs_chirho: &[LedgerLegChirho],
        op_chirho: &LedgerOpChirho,
    ) -> Result<Vec<LegPostStateChirho>, RejectReasonChirho> {
        let balance_mode_chirho = Self::validate_operation_shape_chirho(legs_chirho, op_chirho)?;

        // Scratch copy of only the touched accounts so a mid-record reject leaves NO change.
        let mut scratch_chirho: BTreeMap<AccountIdChirho, AccountStateChirho> = BTreeMap::new();
        let mut recomputed_chirho: Vec<LegPostStateChirho> = Vec::with_capacity(legs_chirho.len());
        // §11.2 + R5b: conservation is PER asset kind, keyed by the account's STABLE `kind_id` —
        // NEVER the versioned `kind_policy_ref` (revising a kind's policy must not split its
        // conservation and strand money) and never one unitless sum.
        let mut balance_by_kind_chirho: BTreeMap<AssetKindIdChirho, i128> = BTreeMap::new();

        for leg_chirho in legs_chirho {
            let current_chirho = scratch_chirho
                .get(&leg_chirho.account_chirho)
                .copied()
                .unwrap_or_else(|| self.state_chirho(&leg_chirho.account_chirho));

            let before_net_chirho = current_chirho.net_money_chirho();
            let next_chirho = fold_leg_chirho(
                current_chirho,
                &leg_chirho.delta_chirho,
                leg_chirho.amount_chirho,
            )
            .ok_or(RejectReasonChirho::ArithmeticChirho)?;

            // §11.3: the stored post MUST equal fold(true current head, delta) — never trusted as given.
            let recomputed_post_chirho = LegPostStateChirho {
                credits_total_chirho: next_chirho.credits_chirho,
                debits_total_chirho: next_chirho.debits_chirho,
                held_chirho: next_chirho.held_chirho,
            };
            if leg_chirho.post_chirho != recomputed_post_chirho {
                return Err(RejectReasonChirho::PostMismatchChirho);
            }

            // F4 spendable-floor on any leg that can reduce spendable.
            if next_chirho.spendable_chirho() < 0 {
                return Err(RejectReasonChirho::OverdraftChirho);
            }

            *balance_by_kind_chirho
                .entry(leg_chirho.account_chirho.kind_id_chirho.clone())
                .or_default() += next_chirho.net_money_chirho() - before_net_chirho;
            scratch_chirho.insert(leg_chirho.account_chirho.clone(), next_chirho);
            recomputed_chirho.push(recomputed_post_chirho);
        }

        // §11.2 per-kind balance mode: a net-zero op must move NO net money for ANY kind (so a
        // cross-kind transfer that nets zero in total but mints one kind / burns another is REFUSED);
        // Mint/Burn are the value in/out exceptions (sign guaranteed by the 1-Credit / 1-Debit shape).
        if matches!(balance_mode_chirho, BalanceModeChirho::NetZeroChirho)
            && balance_by_kind_chirho
                .values()
                .any(|&delta_chirho| delta_chirho != 0)
        {
            return Err(RejectReasonChirho::NotBalancedChirho);
        }

        // Commit atomically (all legs passed).
        for (account_chirho, state_chirho) in scratch_chirho {
            self.accounts_chirho.insert(account_chirho, state_chirho);
        }
        Ok(recomputed_chirho)
    }
}

/// Journal→conservation-snapshot derivation for the monitor port (CF6 rehearsal Phase A; the
/// #5298 placement ruling — logic here, journal wiring in the composition crate).
pub mod snapshot_adapter_chirho;

#[cfg(test)]
mod tests_chirho;

/// The two-seat differential + admission-RED catalog, bound to B's real log-owned token
/// (`cairn-ledger-log-chirho`, dev-dependency; leaf direction, log never depends on audit).
#[cfg(test)]
mod differential_admission_chirho;
