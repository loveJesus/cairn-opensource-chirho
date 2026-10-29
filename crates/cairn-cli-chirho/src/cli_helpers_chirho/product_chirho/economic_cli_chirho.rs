// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Economic product CLI router for price book, billing, resource, promotion, and credit hold families.

use crate::args_chirho::CommandChirho;
use std::path::Path;

#[path = "economic_chirho/billing_cli_chirho.rs"]
mod billing_cli_chirho;
#[path = "economic_chirho/holds_cli_chirho.rs"]
mod holds_cli_chirho;
#[path = "economic_chirho/ledger_cli_chirho.rs"]
mod ledger_cli_chirho;
#[path = "economic_chirho/pricebook_cli_chirho.rs"]
mod pricebook_cli_chirho;
#[path = "economic_chirho/resource_cli_chirho.rs"]
mod resource_cli_chirho;

pub(crate) fn handle_economic_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    let command_chirho =
        match ledger_cli_chirho::handle_ledger_command_chirho(root_chirho, command_chirho)? {
            Some(command_chirho) => command_chirho,
            None => return Ok(None),
        };
    let command_chirho =
        match pricebook_cli_chirho::handle_pricebook_command_chirho(root_chirho, command_chirho)? {
            Some(command_chirho) => command_chirho,
            None => return Ok(None),
        };
    let command_chirho =
        match billing_cli_chirho::handle_billing_command_chirho(root_chirho, command_chirho)? {
            Some(command_chirho) => command_chirho,
            None => return Ok(None),
        };
    let command_chirho =
        match resource_cli_chirho::handle_resource_command_chirho(root_chirho, command_chirho)? {
            Some(command_chirho) => command_chirho,
            None => return Ok(None),
        };
    holds_cli_chirho::handle_holds_command_chirho(root_chirho, command_chirho)
}
