// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Is this topology plan permitted under the grant this principal actually holds?
//!
//! The production caller for the topology half of the control plane, and it composes three things that
//! each existed and had never been driven from a root together: the durable grant store (the CURRENT
//! signed grant for a principal, replay-protected), the plan store's resolver (the plan a digest names,
//! resolved and RE-HASHED), and the grant bounds check.
//!
//! It REPORTS. Nothing here provisions, drains, or moves a ref, so asking whether a change would be
//! allowed costs no authority and is safe against a live root.
//!
//! Refusals distinguish NOTHING WAS CHECKED from CHECKED AND REFUSED — a missing grant or a dangling
//! plan digest exits non-zero with its own identity rather than coming back as a bounds verdict.
//!
//! ```text
//! cairn-topology-plan-verify-chirho <root> <topology-authority-key> <principal> <plan-digest>
//! ```

use cairn_tenant_placement_authority_chirho::control_plane_authorities_chirho::single_role_verifier_chirho;
use cairn_tenant_placement_authority_chirho::topology_chirho::plan_authority_report_chirho::{
    build_topology_plan_authority_report_chirho, render_topology_plan_authority_report_chirho,
};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE_REFUSAL_CHIRHO: &str = "TopologyPlanVerifyUsageRefusedChirho";

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
    let authority_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let principal_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let plan_digest_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    if arguments_chirho.next().is_some() {
        return Err(USAGE_REFUSAL_CHIRHO.to_string());
    }

    let authority_chirho = single_role_verifier_chirho(&authority_key_chirho)
        .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
    let report_chirho = build_topology_plan_authority_report_chirho(
        &root_chirho,
        &principal_chirho,
        &plan_digest_chirho,
        &authority_chirho,
    )
    .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
    render_topology_plan_authority_report_chirho(&report_chirho)
        .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))
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
