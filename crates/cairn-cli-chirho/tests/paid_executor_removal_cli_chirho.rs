// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use cairn_cli_chirho::args_chirho::{CliChirho, CommandChirho};
use clap::Parser;

#[test]
fn paid_catalog_survives_while_legacy_executor_stays_absent_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let catalog_chirho =
                CliChirho::try_parse_from(["cairn-chirho", "paid-effects"]).unwrap();
            assert!(matches!(
                catalog_chirho.command_chirho,
                CommandChirho::PaidEffectsChirho
            ));

            assert!(CliChirho::try_parse_from([
                "cairn-chirho",
                "invoke-priced",
                "echo_paid_chirho",
                "--caller",
                "alice",
            ])
            .is_err());

            let handler_source_chirho = include_str!(
                "../src/cli_helpers_chirho/product_chirho/economic_chirho/ledger_cli_chirho.rs"
            );
            assert!(handler_source_chirho
                .contains("effect_pricing_chirho::registered_effect_prices_chirho()"));
            assert!(!handler_source_chirho.contains("paid_chirho::"));
        })
        .unwrap()
        .join()
        .unwrap();
}
