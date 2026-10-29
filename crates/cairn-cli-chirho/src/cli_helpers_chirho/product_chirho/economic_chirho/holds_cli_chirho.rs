// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Credit hold CLI helpers split out of dispatch_chirho.rs.

use crate::args_chirho::CommandChirho;
use cairn_chirho::legacy_evidence_readers_chirho;
use cairn_chirho::legacy_holds_evidence_chirho;
use std::path::Path;

pub(super) fn handle_holds_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::HoldsChirho => {
            let records_chirho =
                legacy_evidence_readers_chirho::load_credit_holds_chirho(root_chirho)?;
            if records_chirho.is_empty() {
                println!("(no credit holds)");
            }
            for record_chirho in records_chirho {
                println!(
                    "#{}\t{}\t{:?}\tpayer={}\tauthorized={}\tsettled={}\treleased={}\treserve=#{}",
                    record_chirho.seq_chirho,
                    record_chirho.hold_id_chirho,
                    record_chirho.status_chirho,
                    record_chirho.payer_chirho,
                    record_chirho.authorized_token_chirho,
                    record_chirho.settled_token_chirho,
                    record_chirho.released_token_chirho,
                    record_chirho.reserve_ledger_seq_chirho
                );
            }
            Ok(None)
        }
        CommandChirho::HoldsVerifyChirho => {
            let count_chirho =
                legacy_holds_evidence_chirho::verify_credit_holds_single_road_chirho(root_chirho)?;
            println!("verified {count_chirho} credit hold record(s)");
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}
