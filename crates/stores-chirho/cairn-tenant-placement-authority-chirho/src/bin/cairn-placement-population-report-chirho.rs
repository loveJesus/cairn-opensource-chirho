// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Report the CANDIDATE placement-population digest a human may then pin, and admit nothing.
//!
//! The production loader requires an expected population digest supplied from OUTSIDE the evidence
//! root, so that deleting or truncating placement rows is a mismatch rather than a smaller world. That
//! expectation has to be readable before two reviewed authorities can sign it — this is the read, and
//! only the read.
//!
//! **REPORT, NOT DECISION.** Nothing here admits a placement, moves a ref, or authorises a migration.
//! The digest it prints is a CANDIDATE for operator review; it becomes an expectation only when a
//! human carries it into the separately signed capacity expectation. **Do not wire this into the
//! loader.** A loader that computes its own expectation from the log it is about to read has a check
//! that cannot fail, because the trust anchor would come from the artifact being checked.
//!
//! Every chain, verification and vacuity refusal of the store still applies: this reports a verified
//! candidate or it refuses by identity. A store with no current placements refuses rather than
//! reporting an empty population, because a confident empty here becomes a confident zero reservation
//! one layer up.
//!
//! Output carries tenant ids, revisions, assignment digests and the candidate digest only — no key
//! material, no record bodies, no filesystem paths.

use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::placement_record_store_chirho::report_placement_population_for_review_chirho;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE_REFUSAL_CHIRHO: &str = "PlacementPopulationReportUsageRefusedChirho";

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
    let expected_placement_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let roster_operator_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let geo_plan_authority_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    if arguments_chirho.next().is_some() {
        return Err(USAGE_REFUSAL_CHIRHO.to_string());
    }

    let population_chirho = report_placement_population_for_review_chirho(
        &root_chirho,
        &expected_placement_key_chirho,
        &roster_operator_key_chirho,
        &geo_plan_authority_key_chirho,
    )
    .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;

    let mut rendered_chirho = String::from(
        "placement-population-candidate-chirho: REVIEW ONLY, admits nothing.\n\
         Sign the candidate below into a reviewed capacity expectation only after reviewing these rows.\n",
    );
    for verified_chirho in population_chirho.current_chirho() {
        rendered_chirho.push_str(&format!(
            "  tenant_chirho={} revision_chirho={} assignment_digest_chirho={}\n",
            verified_chirho.intent_chirho().tenant_id_chirho,
            verified_chirho.intent_chirho().revision_chirho,
            verified_chirho.assignment_digest_chirho()
        ));
    }
    rendered_chirho.push_str(&format!(
        "candidate_population_digest_chirho={}",
        population_chirho.population_digest_chirho()
    ));
    Ok(rendered_chirho)
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
