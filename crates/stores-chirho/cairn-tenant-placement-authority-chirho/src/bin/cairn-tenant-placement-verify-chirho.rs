// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use cairn_tenant_placement_authority_chirho::population_projection_chirho::{
    load_and_project_tenant_placement_population_chirho,
    render_tenant_placement_population_projection_chirho,
};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE_REFUSAL_CHIRHO: &str = "TenantPlacementPopulationProjectionUsageRefusedChirho";

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
    let record_path_chirho = PathBuf::from(next_utf8_chirho(&mut arguments_chirho)?);
    let expected_placement_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let roster_operator_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let geo_plan_authority_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    if arguments_chirho.next().is_some() {
        return Err(USAGE_REFUSAL_CHIRHO.to_string());
    }

    let projection_chirho = load_and_project_tenant_placement_population_chirho(
        &record_path_chirho,
        &expected_placement_key_chirho,
        &roster_operator_key_chirho,
        &geo_plan_authority_key_chirho,
    )
    .map_err(|error_chirho| error_chirho.to_string())?;
    render_tenant_placement_population_projection_chirho(&projection_chirho)
        .map_err(|error_chirho| error_chirho.to_string())
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
