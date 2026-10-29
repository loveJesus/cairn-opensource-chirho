// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16

//! Data residency CLI helpers split out of dispatch_chirho.rs.

use crate::args_chirho::CommandChirho;
use crate::dag_cli_chirho::parse_placement_candidate_chirho;
use cairn_chirho::data_residency_chirho;
use std::path::Path;

pub(crate) fn handle_data_residency_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::DataResidencySetChirho(args_chirho) => {
            let crate::args_chirho::compliance_args_chirho::DataResidencySetArgsChirho {
                data_regions_chirho,
                processing_regions_chirho,
                operator_chirho,
                allow_unattested_processing_chirho,
            } = args_chirho;
            let (policy_chirho, record_chirho) =
                data_residency_chirho::set_data_residency_policy_chirho(
                    root_chirho,
                    data_regions_chirho,
                    processing_regions_chirho,
                    operator_chirho,
                    !allow_unattested_processing_chirho,
                )?;
            let report_chirho = data_residency_chirho::data_residency_policy_set_report_chirho(
                policy_chirho,
                record_chirho,
            );
            println!("{}", serde_json::to_string_pretty(&report_chirho)?);
            Ok(true)
        }
        CommandChirho::DataResidencyShowChirho => {
            if let Some((policy_hash_chirho, policy_chirho)) =
                data_residency_chirho::current_data_residency_policy_chirho(root_chirho)?
            {
                let report_chirho =
                    data_residency_chirho::data_residency_policy_current_report_chirho(
                        policy_hash_chirho,
                        policy_chirho,
                    );
                println!("{}", serde_json::to_string_pretty(&report_chirho)?);
            } else {
                println!("(no data residency policy)");
            }
            Ok(true)
        }
        CommandChirho::DataResidencyAttestChirho(args_chirho) => {
            let crate::args_chirho::compliance_args_chirho::DataResidencyAttestArgsChirho {
                host_region_chirho,
                processing_region_chirho,
                data_region_chirho,
                region_source_chirho,
                operator_chirho,
            } = args_chirho;
            let (attestation_chirho, record_chirho) =
                data_residency_chirho::attest_data_residency_chirho(
                    root_chirho,
                    host_region_chirho,
                    processing_region_chirho,
                    data_region_chirho,
                    region_source_chirho,
                    operator_chirho,
                )?;
            let report_chirho = data_residency_chirho::data_residency_attestation_report_chirho(
                attestation_chirho,
                record_chirho,
            );
            println!("{}", serde_json::to_string_pretty(&report_chirho)?);
            Ok(true)
        }
        CommandChirho::DataResidencyCheckPlacementChirho(args_chirho) => {
            let crate::args_chirho::compliance_args_chirho::DataResidencyCheckPlacementArgsChirho {
                candidate_chirho,
            } = args_chirho;
            let candidate_chirho = parse_placement_candidate_chirho(candidate_chirho)?;
            let check_chirho = data_residency_chirho::check_placement_candidate_residency_chirho(
                root_chirho,
                &candidate_chirho,
            )?;
            println!("{}", serde_json::to_string_pretty(&check_chirho)?);
            Ok(true)
        }
        _ => Ok(false),
    }
}
