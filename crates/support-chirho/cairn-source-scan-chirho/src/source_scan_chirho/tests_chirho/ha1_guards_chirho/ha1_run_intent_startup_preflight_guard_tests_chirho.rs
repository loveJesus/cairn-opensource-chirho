// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

const AUDIT_CLI_CHIRHO: &str =
    "crates/cairn-cli-chirho/src/cli_helpers_chirho/operations_chirho/audit_cli_chirho.rs";
const RUN_INTENT_PREFLIGHT_SERVICE_CHIRHO: &str =
    "crates/services-chirho/cairn-run-intent-preflight-chirho/src/lib.rs";
/// Bound the preflight dispatch arm WITHOUT pinning a neighbouring legacy command name: the arm
/// ends at the earliest following `CommandChirho::` arm, or at the match fallback if it is the last
/// one. A fixed neighbour landmark breaks every time that neighbour is deleted (CF6 D1 hit exactly
/// that), and a missing landmark would silently widen the forbidden-token scan to end of file.
fn preflight_arm_region_chirho<'a>(text_chirho: &'a str, start_marker_chirho: &str) -> &'a str {
    let start_chirho = text_chirho
        .find(start_marker_chirho)
        .unwrap_or_else(|| panic!("missing start marker {start_marker_chirho}"));
    let body_start_chirho = start_chirho + start_marker_chirho.len();
    let after_chirho = &text_chirho[body_start_chirho..];
    let next_arm_chirho = after_chirho.find("CommandChirho::");
    let fallback_chirho = after_chirho.find("_ => Ok(false),");
    let end_chirho = match (next_arm_chirho, fallback_chirho) {
        (Some(next_chirho), Some(fall_chirho)) => next_chirho.min(fall_chirho),
        (Some(next_chirho), None) => next_chirho,
        (None, Some(fall_chirho)) => fall_chirho,
        (None, None) => panic!("missing preflight arm end boundary (no next arm, no fallback)"),
    };
    &text_chirho[start_chirho..body_start_chirho + end_chirho]
}

fn forbidden_preflight_tokens_chirho() -> [&'static str; 11] {
    [
        "resume_unfinished_run_intents_chirho(",
        "append_run_intent_record_chirho(",
        "run_dag_with_intent_chirho(",
        "run_dag_with_private_input_intent_chirho(",
        "run_admitted_dag_chirho(",
        "transfer_chirho(",
        "create_stripe_transfer_chirho(",
        "settle_credit_hold_chirho(",
        "gate1_authority_flip",
        "gate1_authority_rollback",
        "gate1_authority_backfill",
    ]
}

fn forbidden_preflight_sites_chirho(region_chirho: &str) -> Vec<&'static str> {
    forbidden_preflight_tokens_chirho()
        .into_iter()
        .filter(|token_chirho| region_chirho.contains(token_chirho))
        .collect()
}

#[test]
fn run_intent_startup_preflight_stays_read_only_chirho() {
    let audit_cli_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(AUDIT_CLI_CHIRHO)).unwrap();
    let audit_region_chirho = preflight_arm_region_chirho(
        &audit_cli_chirho,
        "CommandChirho::RunIntentStartupPreflightChirho",
    );
    assert!(
        audit_cli_chirho.contains(
            "run_run_intent_startup_preflight_command_chirho as run_intent_preflight_command_chirho"
        ),
        "CLI preflight arm must import the read-only service command helper"
    );
    assert!(
        audit_region_chirho.contains("run_intent_preflight_command_chirho("),
        "CLI preflight arm must delegate to the read-only report helper"
    );

    let preflight_service_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(RUN_INTENT_PREFLIGHT_SERVICE_CHIRHO))
            .unwrap();
    assert!(
        preflight_service_chirho.contains("run_intent_startup_preflight_report_chirho("),
        "preflight helper must keep a named report builder"
    );
    assert!(
        preflight_service_chirho.contains("check_run_intent_resume_prerequisites_chirho("),
        "preflight helper must keep a named prerequisite-only checker"
    );
    let combined_chirho = format!("{audit_region_chirho}\n{preflight_service_chirho}");
    let offenders_chirho = forbidden_preflight_sites_chirho(&combined_chirho);
    assert!(
        offenders_chirho.is_empty(),
        "run-intent startup preflight must stay prerequisite-check-only and read-only: {offenders_chirho:?}"
    );
}

#[test]
fn run_intent_startup_preflight_guard_fixture_catches_mutating_resume_chirho() {
    let planted_chirho = "run_intent_startup_preflight_report_chirho(root_chirho);\nresume_unfinished_run_intents_chirho(root_chirho)?;";
    let offenders_chirho = forbidden_preflight_sites_chirho(planted_chirho);
    assert_eq!(
        offenders_chirho,
        vec!["resume_unfinished_run_intents_chirho("],
        "fixture must catch the mutating startup-resume call in the preflight path"
    );
}

#[test]
fn preflight_arm_region_stops_before_the_next_arm_chirho() {
    let planted_chirho = concat!(
        "        CommandChirho::RunIntentStartupPreflightChirho(args_chirho) => handled_chirho(\n",
        "            run_intent_preflight_command_chirho(root_chirho, args_chirho),\n",
        "        ),\n",
        "        CommandChirho::SomeLaterArmChirho { .. } => {\n",
        "            transfer_chirho(root_chirho);\n",
        "        }\n",
        "        _ => Ok(false),\n",
    );
    let region_chirho = preflight_arm_region_chirho(
        planted_chirho,
        "CommandChirho::RunIntentStartupPreflightChirho",
    );
    assert!(
        region_chirho.contains("run_intent_preflight_command_chirho"),
        "the preflight arm itself must be inside the extracted region"
    );
    assert!(
        !region_chirho.contains("transfer_chirho("),
        "extraction must stop before the following arm; a planted mutating token leaked in"
    );
    assert!(
        !region_chirho.contains("SomeLaterArmChirho"),
        "extraction must not reach the following arm header"
    );
}
