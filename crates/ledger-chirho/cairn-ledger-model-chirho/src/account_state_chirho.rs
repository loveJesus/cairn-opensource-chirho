// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Pure checked account-state arithmetic shared by journal verification, money audit, and derived
//! read models. One implementation defines account net and spendable money for every caller.

use crate::record_chirho::LegDeltaChirho;

/// One account's running totals. Conserved money is `credits - debits`; `held` is spendable money
/// reserved by a hold but not yet spent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccountStateChirho {
    pub credits_chirho: u64,
    pub debits_chirho: u64,
    pub held_chirho: u64,
}

impl AccountStateChirho {
    /// Spendable balance. Signed output makes an invalid over-debit visible instead of wrapping.
    pub fn spendable_chirho(&self) -> i128 {
        self.credits_chirho as i128 - self.debits_chirho as i128 - self.held_chirho as i128
    }

    /// Conserved account money. A hold changes availability, not ownership.
    pub fn net_money_chirho(&self) -> i128 {
        self.credits_chirho as i128 - self.debits_chirho as i128
    }
}

/// Fold one leg delta onto an account state with checked arithmetic. `None` is a typed caller-side
/// refusal signal for overflow or underflow; money never wraps.
pub fn fold_leg_chirho(
    state_chirho: AccountStateChirho,
    delta_chirho: &LegDeltaChirho,
    amount_chirho: u64,
) -> Option<AccountStateChirho> {
    let mut next_chirho = state_chirho;
    match delta_chirho {
        LegDeltaChirho::CreditChirho => {
            next_chirho.credits_chirho = next_chirho.credits_chirho.checked_add(amount_chirho)?;
        }
        LegDeltaChirho::DebitChirho => {
            next_chirho.debits_chirho = next_chirho.debits_chirho.checked_add(amount_chirho)?;
        }
        LegDeltaChirho::HoldChirho => {
            next_chirho.held_chirho = next_chirho.held_chirho.checked_add(amount_chirho)?;
        }
        LegDeltaChirho::ReleaseChirho => {
            next_chirho.held_chirho = next_chirho.held_chirho.checked_sub(amount_chirho)?;
        }
        LegDeltaChirho::FinalizeChirho => {
            next_chirho.held_chirho = next_chirho.held_chirho.checked_sub(amount_chirho)?;
            next_chirho.debits_chirho = next_chirho.debits_chirho.checked_add(amount_chirho)?;
        }
    }
    Some(next_chirho)
}

#[cfg(test)]
mod account_state_tests_chirho {
    use super::*;

    #[test]
    fn account_net_excludes_held_while_spendable_includes_it_chirho() {
        let state_chirho = AccountStateChirho {
            credits_chirho: 100,
            debits_chirho: 20,
            held_chirho: 30,
        };
        assert_eq!(state_chirho.net_money_chirho(), 80);
        assert_eq!(state_chirho.spendable_chirho(), 50);
    }

    #[test]
    fn checked_leg_fold_refuses_underflow_and_overflow_chirho() {
        assert!(fold_leg_chirho(
            AccountStateChirho::default(),
            &LegDeltaChirho::ReleaseChirho,
            1,
        )
        .is_none());
        assert!(fold_leg_chirho(
            AccountStateChirho {
                credits_chirho: u64::MAX,
                ..AccountStateChirho::default()
            },
            &LegDeltaChirho::CreditChirho,
            1,
        )
        .is_none());
    }
}
