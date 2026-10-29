// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Report the CANDIDATE capacity/load snapshot digest a human may then pin, and admit nothing.
//!
//! The production admission adapter compares the exact bounded bytes of the capacity, lifecycle,
//! and usage logs with an expectation supplied from OUTSIDE the evidence root. This command makes
//! that candidate readable without making it authoritative.
//!
//! **REPORT, NOT DECISION.** This command does not verify signatures, admit a placement, move a ref,
//! or author a signed expectation. Run the strict placement-control verifier first, review the three
//! logs, and then carry this candidate into the custody-separated two-party expectation flow. Never
//! call this command from the admission loader: deriving the expectation from the artifact being
//! checked would make truncation detection self-certifying.
//!
//! Output contains one public digest and fixed review text only. It never prints the evidence-root
//! path, log bytes, records, or key material.

use cairn_tenant_placement_authority_chirho::capacity_admission_impl_chirho::capacity_load_snapshot_digest_chirho;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE_REFUSAL_CHIRHO: &str = "CapacityLoadSnapshotReportUsageRefusedChirho";
const ROOT_REFUSAL_CHIRHO: &str = "CapacityLoadSnapshotReportRootRefusedChirho";

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
    let evidence_root_chirho = PathBuf::from(next_utf8_chirho(&mut arguments_chirho)?);
    if arguments_chirho.next().is_some() {
        return Err(USAGE_REFUSAL_CHIRHO.to_string());
    }

    let metadata_chirho = std::fs::symlink_metadata(&evidence_root_chirho)
        .map_err(|_error_chirho| ROOT_REFUSAL_CHIRHO.to_string())?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_dir() {
        return Err(ROOT_REFUSAL_CHIRHO.to_string());
    }

    let digest_chirho = capacity_load_snapshot_digest_chirho(&evidence_root_chirho)
        .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
    Ok(format!(
        "capacity-load-snapshot-candidate-chirho: REVIEW ONLY, admits nothing.\n\
         This binds the exact bounded bytes of the capacity, lifecycle, and usage logs.\n\
         It does not verify those records; run the strict verifier before pinning it externally.\n\
         candidate_capacity_load_snapshot_digest_chirho={digest_chirho}"
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
