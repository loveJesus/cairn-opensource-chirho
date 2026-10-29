// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Price book CLI helpers split out of economic_cli_chirho.rs.

use crate::args_chirho::CommandChirho;
use crate::parse_helpers_chirho::parse_effect_prices_chirho;
use cairn_chirho::effect_pricing_chirho;
use std::path::Path;

pub(super) fn handle_pricebook_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::PriceBookSetChirho(args_chirho) => {
            let crate::args_chirho::economic_args_chirho::PriceBookSetArgsChirho {
                app_chirho,
                owner_chirho,
                request_price_chirho,
                effect_prices_chirho,
                external_markup_bps_chirho,
            } = args_chirho;
            let effect_price_map_chirho = parse_effect_prices_chirho(&effect_prices_chirho)?;
            let (hash_chirho, book_chirho, record_chirho) =
                effect_pricing_chirho::set_price_book_chirho(
                    root_chirho,
                    &app_chirho,
                    &owner_chirho,
                    request_price_chirho,
                    effect_price_map_chirho,
                    external_markup_bps_chirho,
                )?;
            println!(
                "price book for '{app_chirho}' -> {} owner={} record #{}",
                hash_chirho.0, owner_chirho, record_chirho.seq_chirho
            );
            if let Some(price_chirho) = book_chirho.price_per_request_chirho {
                println!("  request price: {price_chirho} token");
            }
            for (effect_chirho, price_chirho) in &book_chirho.effect_prices_chirho {
                println!("  {effect_chirho}: {price_chirho} token");
            }
            println!(
                "  external markup (reserved): {} bps",
                book_chirho.external_markup_bps_chirho
            );
            if let Some(previous_chirho) = book_chirho.previous_chirho {
                println!("  previous: {}", previous_chirho.0);
            }
            println!("  rollback: rollback pricebook/{app_chirho} <hash>");
            Ok(None)
        }
        CommandChirho::PriceBookShowChirho { app_chirho } => {
            match effect_pricing_chirho::current_price_book_chirho(root_chirho, &app_chirho)? {
                Some((hash_chirho, book_chirho)) => {
                    println!("price book for '{app_chirho}' -> {}", hash_chirho.0);
                    println!("  owner: {}", book_chirho.owner_principal_chirho);
                    if let Some(price_chirho) = book_chirho.price_per_request_chirho {
                        println!("  request price: {price_chirho} token");
                    } else {
                        println!("  request price: (none)");
                    }
                    if book_chirho.effect_prices_chirho.is_empty() {
                        println!("  effect prices: (none)");
                    } else {
                        for (effect_chirho, price_chirho) in &book_chirho.effect_prices_chirho {
                            println!("  {effect_chirho}: {price_chirho} token");
                        }
                    }
                    println!(
                        "  external markup (reserved): {} bps",
                        book_chirho.external_markup_bps_chirho
                    );
                    if let Some(previous_chirho) = book_chirho.previous_chirho {
                        println!("  previous: {}", previous_chirho.0);
                    }
                    println!("  rollback: rollback pricebook/{app_chirho} <hash>");
                }
                None => println!("no current price book for app '{app_chirho}'"),
            }
            Ok(None)
        }
        CommandChirho::PriceBookHistoryChirho { app_chirho } => {
            let current_chirho =
                effect_pricing_chirho::current_price_book_hash_chirho(root_chirho, &app_chirho)?;
            let records_chirho =
                effect_pricing_chirho::price_book_history_chirho(root_chirho, &app_chirho)?;
            if records_chirho.is_empty() {
                println!("(no price books for app '{app_chirho}')");
            }
            for record_chirho in &records_chirho {
                let current_marker_chirho =
                    if Some(&record_chirho.price_book_chirho) == current_chirho.as_ref() {
                        " current"
                    } else {
                        ""
                    };
                let previous_chirho = record_chirho
                    .previous_chirho
                    .as_ref()
                    .map(|hash_chirho| hash_chirho.0.as_str())
                    .unwrap_or("(none)");
                println!(
                    "#{}\t{}{}\towner={}\tprevious={}\tat_ms={}",
                    record_chirho.seq_chirho,
                    record_chirho.price_book_chirho.0,
                    current_marker_chirho,
                    record_chirho.owner_principal_chirho,
                    previous_chirho,
                    record_chirho.at_ms_chirho
                );
            }
            println!("rollback: rollback pricebook/{app_chirho} <hash>");
            Ok(None)
        }
        CommandChirho::PriceBookVerifyChirho => {
            let count_chirho = effect_pricing_chirho::verify_price_books_chirho(root_chirho)?;
            println!("verified {count_chirho} price book record(s)");
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}
