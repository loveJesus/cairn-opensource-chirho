// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Verify one authored tenant-placement record and append it to a root's placement store.
//!
//! The authoring binary can produce a signed record and had nowhere to put it: measured 2026-08-21,
//! `append_verified_placement_record_chirho` had zero callers outside its own module, so no placement
//! record could enter a store at all and the reserved-capacity population could never be non-empty.
//! This is that missing step, and nothing more.
//!
//! **It decides nothing.** The record must already verify against the three supplied authority keys;
//! this appends it or refuses by identity. An exact duplicate is idempotent and appends nothing; a
//! different record at a revision already taken refuses as a fork.
//!
//! Output carries tenant id, revision and the assignment digest only — no key material, no record
//! body, no filesystem paths.

use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::placement_record_store_chirho::append_verified_placement_record_chirho;
use cairn_tenant_placement_authority_chirho::{
    TenantPlacementRecordChirho, TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO,
};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE_REFUSAL_CHIRHO: &str = "PlacementRecordAppendUsageRefusedChirho";
const RECORD_UNREADABLE_REFUSAL_CHIRHO: &str = "PlacementRecordFileUnreadableChirho";
const RECORD_MALFORMED_REFUSAL_CHIRHO: &str = "PlacementRecordFileMalformedChirho";

fn next_utf8_chirho(
    arguments_chirho: &mut impl Iterator<Item = OsString>,
) -> Result<String, &'static str> {
    arguments_chirho
        .next()
        .ok_or(USAGE_REFUSAL_CHIRHO)?
        .into_string()
        .map_err(|_value_chirho| USAGE_REFUSAL_CHIRHO)
}

fn run_chirho() -> Result<String, String> {
    let mut arguments_chirho = std::env::args_os();
    let _program_chirho = arguments_chirho.next();
    let root_chirho = PathBuf::from(next_utf8_chirho(&mut arguments_chirho)?);
    let record_path_chirho = PathBuf::from(next_utf8_chirho(&mut arguments_chirho)?);
    let expected_placement_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let roster_operator_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let geo_plan_authority_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    if arguments_chirho.next().is_some() {
        return Err(USAGE_REFUSAL_CHIRHO.to_string());
    }

    // The same identity-stable bounded primitive the stores read through: a record file that is
    // hard-linked, or replaced between the stat and the read, is not one this will accept.
    let bytes_chirho = cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &record_path_chirho,
        TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO,
    )
    .map_err(|_error_chirho| RECORD_UNREADABLE_REFUSAL_CHIRHO.to_string())?;
    let record_chirho: TenantPlacementRecordChirho = serde_json::from_slice(&bytes_chirho)
        .map_err(|_error_chirho| RECORD_MALFORMED_REFUSAL_CHIRHO.to_string())?;

    let verified_chirho = append_verified_placement_record_chirho(
        &root_chirho,
        record_chirho,
        &expected_placement_key_chirho,
        &roster_operator_key_chirho,
        &geo_plan_authority_key_chirho,
    )
    .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;

    Ok(format!(
        "tenant_chirho={} revision_chirho={} assignment_digest_chirho={}",
        verified_chirho.intent_chirho().tenant_id_chirho,
        verified_chirho.intent_chirho().revision_chirho,
        verified_chirho.assignment_digest_chirho()
    ))
}

fn main() -> ExitCode {
    match run_chirho() {
        Ok(rendered_chirho) => {
            println!("{rendered_chirho}");
            ExitCode::SUCCESS
        }
        Err(identity_chirho) => {
            eprintln!("{identity_chirho}");
            ExitCode::FAILURE
        }
    }
}
