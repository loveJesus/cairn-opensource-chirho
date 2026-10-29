// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use cairn_cli_chirho::args_chirho::{CliChirho, CommandChirho};
use clap::Parser;

#[test]
fn reversion_mutation_commands_are_removed_while_evidence_commands_remain_chirho() {
    for removed_command_chirho in [
        "reversion-grant",
        "causal-rollback",
        "reversion-complete",
        "reversion-demo",
        "reversion-resolve-manual",
    ] {
        assert!(
            CliChirho::try_parse_from(["cairn-chirho", removed_command_chirho]).is_err(),
            "removed reversion mutation command still parses: {removed_command_chirho}"
        );
    }

    for (evidence_command_chirho, expected_command_chirho) in [
        ("reversion-events", "events"),
        ("reversion-compensations", "compensations"),
        ("reversion-executions", "executions"),
        ("reversion-completions", "completions"),
        ("reversion-verify", "verify"),
        ("reversion-manual-resolutions", "manual-resolutions"),
    ] {
        let cli_chirho = CliChirho::try_parse_from(["cairn-chirho", evidence_command_chirho])
            .expect("retained reversion evidence command must parse");
        let actual_command_chirho = match cli_chirho.command_chirho {
            CommandChirho::ReversionEventsChirho => "events",
            CommandChirho::ReversionCompensationsChirho => "compensations",
            CommandChirho::ReversionExecutionsChirho => "executions",
            CommandChirho::ReversionCompletionsChirho => "completions",
            CommandChirho::ReversionVerifyChirho => "verify",
            CommandChirho::ReversionManualResolutionsChirho => "manual-resolutions",
            other_chirho => panic!(
                "unexpected retained command: {:?}",
                std::mem::discriminant(&other_chirho)
            ),
        };
        assert_eq!(actual_command_chirho, expected_command_chirho);
    }
}
