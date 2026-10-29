// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! `tree-generate-chirho` — G1 operator-run brief-to-source generation.

use cairn_tree_generate_chirho::{
    run_tree_generation_chirho, GenerateOptionsChirho, ProviderModeChirho, StubScenarioChirho,
};
use std::path::PathBuf;
use std::process::ExitCode;

const HELP_CHIRHO: &str = "\
usage: tree-generate-chirho --brief <json> --output <app_root> --runtime-root <root> --owner <owner> --tree-build <path> --cairn-cli <path> --json [options]

Options:
  --provider deterministic-stub-chirho|openrouter-chirho
  --stub-scenario valid-contact-chirho|hostile-capability-chirho|broken-loop-chirho
  --provider-config-secret <name>
  --authoring-context <json>
  --max-iterations <n>
  --max-provider-calls <n>
";

fn main() -> ExitCode {
    let args_chirho: Vec<String> = std::env::args().collect();
    if args_chirho
        .iter()
        .any(|arg_chirho| arg_chirho == "--help" || arg_chirho == "-h")
    {
        println!("{HELP_CHIRHO}");
        return ExitCode::SUCCESS;
    }
    let options_chirho = match parse_options_chirho(&args_chirho) {
        Ok(options_chirho) => options_chirho,
        Err(error_chirho) => {
            eprintln!("{error_chirho}");
            eprintln!("{HELP_CHIRHO}");
            return ExitCode::from(2);
        }
    };
    let report_chirho = run_tree_generation_chirho(&options_chirho);
    println!("{}", serde_json::to_string_pretty(&report_chirho).unwrap());
    if report_chirho.ok_chirho {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn parse_options_chirho(args_chirho: &[String]) -> Result<GenerateOptionsChirho, String> {
    let mut brief_path_chirho = None;
    let mut output_root_chirho = None;
    let mut runtime_root_chirho = None;
    let mut owner_chirho = None;
    let mut provider_mode_chirho = ProviderModeChirho::DeterministicStubChirho;
    let mut stub_scenario_chirho = StubScenarioChirho::ValidContactChirho;
    let mut provider_config_secret_chirho = None;
    let mut authoring_context_chirho = None;
    let mut tree_build_chirho = None;
    let mut cairn_cli_chirho = None;
    let mut max_iterations_chirho = 2usize;
    let mut max_provider_calls_chirho = 2usize;
    let mut json_chirho = false;

    let mut i_chirho = 1usize;
    while i_chirho < args_chirho.len() {
        match args_chirho[i_chirho].as_str() {
            "--brief" => {
                brief_path_chirho = Some(PathBuf::from(value_chirho(args_chirho, i_chirho)?));
                i_chirho += 2;
            }
            "--output" => {
                output_root_chirho = Some(PathBuf::from(value_chirho(args_chirho, i_chirho)?));
                i_chirho += 2;
            }
            "--runtime-root" => {
                runtime_root_chirho = Some(PathBuf::from(value_chirho(args_chirho, i_chirho)?));
                i_chirho += 2;
            }
            "--owner" => {
                owner_chirho = Some(value_chirho(args_chirho, i_chirho)?.to_string());
                i_chirho += 2;
            }
            "--provider" => {
                provider_mode_chirho = match value_chirho(args_chirho, i_chirho)? {
                    "deterministic-stub-chirho" => ProviderModeChirho::DeterministicStubChirho,
                    "openrouter-chirho" => ProviderModeChirho::OpenRouterChirho,
                    other_chirho => return Err(format!("unknown provider {other_chirho}")),
                };
                i_chirho += 2;
            }
            "--stub-scenario" => {
                stub_scenario_chirho = match value_chirho(args_chirho, i_chirho)? {
                    "valid-contact-chirho" => StubScenarioChirho::ValidContactChirho,
                    "hostile-capability-chirho" => StubScenarioChirho::HostileCapabilityChirho,
                    "broken-loop-chirho" => StubScenarioChirho::BrokenLoopChirho,
                    other_chirho => return Err(format!("unknown stub scenario {other_chirho}")),
                };
                i_chirho += 2;
            }
            "--provider-config-secret" => {
                provider_config_secret_chirho =
                    Some(value_chirho(args_chirho, i_chirho)?.to_string());
                i_chirho += 2;
            }
            "--authoring-context" => {
                authoring_context_chirho =
                    Some(PathBuf::from(value_chirho(args_chirho, i_chirho)?));
                i_chirho += 2;
            }
            "--tree-build" => {
                tree_build_chirho = Some(PathBuf::from(value_chirho(args_chirho, i_chirho)?));
                i_chirho += 2;
            }
            "--cairn-cli" => {
                cairn_cli_chirho = Some(PathBuf::from(value_chirho(args_chirho, i_chirho)?));
                i_chirho += 2;
            }
            "--max-iterations" => {
                max_iterations_chirho = parse_usize_chirho(value_chirho(args_chirho, i_chirho)?)?;
                i_chirho += 2;
            }
            "--max-provider-calls" => {
                max_provider_calls_chirho =
                    parse_usize_chirho(value_chirho(args_chirho, i_chirho)?)?;
                i_chirho += 2;
            }
            "--json" => {
                json_chirho = true;
                i_chirho += 1;
            }
            other_chirho => return Err(format!("unknown argument {other_chirho}")),
        }
    }
    if !json_chirho {
        return Err("--json is required for schema-tagged G1 evidence".to_string());
    }
    Ok(GenerateOptionsChirho {
        brief_path_chirho: brief_path_chirho.ok_or_else(|| "--brief is required".to_string())?,
        output_root_chirho: output_root_chirho.ok_or_else(|| "--output is required".to_string())?,
        runtime_root_chirho: runtime_root_chirho
            .ok_or_else(|| "--runtime-root is required".to_string())?,
        owner_chirho: owner_chirho.ok_or_else(|| "--owner is required".to_string())?,
        provider_mode_chirho,
        stub_scenario_chirho,
        provider_config_secret_chirho,
        authoring_context_chirho,
        tree_build_chirho: tree_build_chirho
            .ok_or_else(|| "--tree-build is required".to_string())?,
        cairn_cli_chirho: cairn_cli_chirho.ok_or_else(|| "--cairn-cli is required".to_string())?,
        max_iterations_chirho,
        max_provider_calls_chirho,
    })
}

fn value_chirho(args_chirho: &[String], index_chirho: usize) -> Result<&str, String> {
    args_chirho
        .get(index_chirho + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("{} requires a value", args_chirho[index_chirho]))
}

fn parse_usize_chirho(value_chirho: &str) -> Result<usize, String> {
    value_chirho
        .parse::<usize>()
        .map_err(|_| format!("expected positive integer, got {value_chirho}"))
}
