// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16

//! Onboarding CLI helpers split out of dispatch_chirho.rs.

use crate::args_chirho::CommandChirho;
use cairn_chirho::onboarding_chirho;
use std::path::Path;

pub(crate) fn handle_onboarding_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::OnboardingSetChirho(args_chirho) => {
            let crate::args_chirho::content_args_chirho::OnboardingSetArgsChirho {
                app_chirho,
                owner_chirho,
                title_chirho,
                steps_chirho,
            } = args_chirho;
            let steps_val_chirho: Vec<onboarding_chirho::OnboardingStepChirho> = steps_chirho
                .iter()
                .map(|step_chirho| {
                    onboarding_chirho::parse_onboarding_step_spec_chirho(step_chirho)
                })
                .collect::<anyhow::Result<_>>()?;
            let (hash_chirho, guide_chirho, record_chirho) =
                onboarding_chirho::set_onboarding_guide_chirho(
                    root_chirho,
                    &app_chirho,
                    &owner_chirho,
                    &title_chirho,
                    steps_val_chirho,
                )?;
            println!(
                "onboarding '{}' -> {} seq=#{} steps={}",
                guide_chirho.app_chirho,
                hash_chirho.0,
                record_chirho.seq_chirho,
                guide_chirho.steps_chirho.len()
            );
            Ok(None)
        }
        CommandChirho::OnboardingShowChirho { app_chirho } => {
            match onboarding_chirho::current_onboarding_guide_chirho(root_chirho, &app_chirho)? {
                Some((hash_chirho, guide_chirho)) => {
                    println!("onboarding '{app_chirho}' -> {}", hash_chirho.0);
                    println!("  owner: {}", guide_chirho.owner_principal_chirho);
                    println!("  title: {}", guide_chirho.title_chirho);
                    for (i_chirho, step_chirho) in guide_chirho.steps_chirho.iter().enumerate() {
                        let target_chirho = step_chirho
                            .target_chirho
                            .as_deref()
                            .map(|target_chirho| format!(" target={target_chirho}"))
                            .unwrap_or_default();
                        println!(
                            "  {}. {}{} -- {}",
                            i_chirho + 1,
                            step_chirho.title_chirho,
                            target_chirho,
                            step_chirho.body_chirho
                        );
                    }
                }
                None => println!("no onboarding guide for '{app_chirho}'"),
            }
            Ok(None)
        }
        CommandChirho::OnboardingHistoryChirho { app_chirho } => {
            let current_chirho =
                onboarding_chirho::current_onboarding_hash_chirho(root_chirho, &app_chirho)?;
            let records_chirho =
                onboarding_chirho::onboarding_history_chirho(root_chirho, &app_chirho)?;
            if records_chirho.is_empty() {
                println!("(no onboarding history)");
            }
            for record_chirho in &records_chirho {
                let current_marker_chirho =
                    if current_chirho.as_ref() == Some(&record_chirho.guide_chirho) {
                        " current"
                    } else {
                        ""
                    };
                println!(
                    "#{}\t{}\towner={}\tprevious={}\tat_ms={}{}",
                    record_chirho.seq_chirho,
                    record_chirho.guide_chirho.0,
                    record_chirho.owner_principal_chirho,
                    record_chirho
                        .previous_chirho
                        .as_ref()
                        .map(|hash_chirho| hash_chirho.0.as_str())
                        .unwrap_or("(none)"),
                    record_chirho.at_ms_chirho,
                    current_marker_chirho
                );
            }
            Ok(None)
        }
        CommandChirho::OnboardingVerifyChirho => {
            let count_chirho = onboarding_chirho::verify_onboarding_chirho(root_chirho)?;
            println!("verified {count_chirho} onboarding record(s)");
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}
