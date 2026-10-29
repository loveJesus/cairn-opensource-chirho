// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16

//! Ledger, gas, and paid-effect CLI helpers split out of dispatch_chirho.rs.

use crate::args_chirho::CommandChirho;
use cairn_chirho::{effect_pricing_chirho, legacy_ledger_evidence_chirho};
use std::path::Path;

pub(super) fn handle_ledger_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::LedgerBalancesChirho => {
            let balances_chirho =
                legacy_ledger_evidence_chirho::verified_balances_chirho(root_chirho)?;
            if balances_chirho.is_empty() {
                println!("(empty ledger)");
            }
            for ((account_chirho, asset_chirho), amount_chirho) in &balances_chirho {
                println!("{account_chirho}\t{asset_chirho:?}\t{amount_chirho}");
            }
            Ok(None)
        }
        CommandChirho::LedgerVerifyChirho => {
            let count_chirho = legacy_ledger_evidence_chirho::verify_ledger_chirho(root_chirho)?;
            println!("ledger OK: {count_chirho} entries — all contiguous, balanced, and signed");
            Ok(None)
        }
        CommandChirho::PaidEffectsChirho => {
            for (name_chirho, price_chirho, provider_chirho) in
                effect_pricing_chirho::registered_effect_prices_chirho()
            {
                println!("{name_chirho}\t{price_chirho} token\t-> {provider_chirho}");
            }
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}
