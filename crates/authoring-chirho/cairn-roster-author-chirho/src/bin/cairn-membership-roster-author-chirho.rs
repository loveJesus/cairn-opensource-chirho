// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use anyhow::{anyhow, Context, Result};
use cairn_roster_author_chirho::roster_authoring_chirho::author_signed_roster_bundle_chirho;
use std::path::PathBuf;

fn main() -> Result<()> {
    let mut args_chirho = std::env::args_os();
    let _program_chirho = args_chirho.next();
    let input_path_chirho = args_chirho.next().map(PathBuf::from).ok_or_else(|| {
        anyhow!(
            "usage: cairn-membership-roster-author-chirho <input.json> <operator-sign-root> <fresh-output-dir>"
        )
    })?;
    let operator_sign_root_chirho =
        args_chirho.next().map(PathBuf::from).ok_or_else(|| {
            anyhow!(
                "usage: cairn-membership-roster-author-chirho <input.json> <operator-sign-root> <fresh-output-dir>"
            )
        })?;
    let output_dir_chirho = args_chirho.next().map(PathBuf::from).ok_or_else(|| {
        anyhow!(
            "usage: cairn-membership-roster-author-chirho <input.json> <operator-sign-root> <fresh-output-dir>"
        )
    })?;
    if args_chirho.next().is_some() {
        return Err(anyhow!(
            "usage: cairn-membership-roster-author-chirho <input.json> <operator-sign-root> <fresh-output-dir>"
        ));
    }
    let report_chirho = author_signed_roster_bundle_chirho(
        &input_path_chirho,
        &operator_sign_root_chirho,
        &output_dir_chirho,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report_chirho)
            .context("RosterAuthoringReportRenderRefusedChirho")?
    );
    Ok(())
}
