// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Read-only realtime evidence CLI plus fail-closed v1 protocol mutation doors.

use crate::args_chirho::CommandChirho;
use crate::display_cli_chirho::{
    realtime_epilogues_list_text_chirho, realtime_events_list_text_chirho,
    realtime_sessions_list_text_chirho,
};
use cairn_chirho::{effect_chirho, realtime_ledger_bound_evidence_chirho};
use std::io::Write;
use std::path::Path;

pub(crate) fn handle_realtime_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::RealtimeOpenChirho(..)
        | CommandChirho::RealtimeEventChirho(..)
        | CommandChirho::RealtimeTickChirho(..)
        | CommandChirho::RealtimeProviderUsageChirho(..)
        | CommandChirho::RealtimeOpenAiUsageImportChirho(..)
        | CommandChirho::RealtimeCloseChirho(..)
        | CommandChirho::RealtimeSweepChirho(..)
        | CommandChirho::RealtimeEpilogueChirho(..) => {
            effect_chirho::refuse_legacy_realtime_money_road_chirho().map(|()| None)
        }
        CommandChirho::RealtimeTranscriptRevealChirho(args_chirho) => {
            let crate::args_chirho::realtime_args_chirho::RealtimeTranscriptRevealArgsChirho {
                session_chirho,
                accessed_by_chirho,
                purpose_chirho,
            } = args_chirho;
            let reveal_chirho =
                realtime_ledger_bound_evidence_chirho::reveal_realtime_transcript_chirho(
                    root_chirho,
                    &session_chirho,
                    &accessed_by_chirho,
                    &purpose_chirho,
                )?;
            std::io::stdout().write_all(&reveal_chirho.plaintext_chirho)?;
            if !reveal_chirho.plaintext_chirho.ends_with(b"\n") {
                std::io::stdout().write_all(b"\n")?;
            }
            Ok(None)
        }
        CommandChirho::RealtimeSessionsChirho => {
            let records_chirho =
                realtime_ledger_bound_evidence_chirho::load_realtime_sessions_for_display_chirho(
                    root_chirho,
                )?;
            if records_chirho.is_empty() {
                println!("(no realtime sessions)");
            }
            print!("{}", realtime_sessions_list_text_chirho(&records_chirho));
            Ok(None)
        }
        CommandChirho::RealtimeEventsChirho => {
            let records_chirho =
                realtime_ledger_bound_evidence_chirho::load_realtime_events_for_display_chirho(
                    root_chirho,
                )?;
            if records_chirho.is_empty() {
                println!("(no realtime events)");
            }
            print!("{}", realtime_events_list_text_chirho(&records_chirho));
            Ok(None)
        }
        CommandChirho::RealtimeVerifyChirho => {
            let (sessions_chirho, events_chirho) =
                realtime_ledger_bound_evidence_chirho::verify_realtime_chirho(root_chirho)?;
            let epilogues_chirho =
                realtime_ledger_bound_evidence_chirho::verify_realtime_epilogues_chirho(
                    root_chirho,
                )?;
            println!(
                "verified {sessions_chirho} realtime session record(s), {events_chirho} realtime event record(s), {epilogues_chirho} realtime epilogue record(s)"
            );
            Ok(None)
        }
        CommandChirho::RealtimeEpiloguesChirho => {
            let records_chirho =
                realtime_ledger_bound_evidence_chirho::load_realtime_epilogues_for_display_chirho(
                    root_chirho,
                )?;
            if records_chirho.is_empty() {
                println!("(no realtime epilogues)");
            }
            print!("{}", realtime_epilogues_list_text_chirho(&records_chirho));
            Ok(None)
        }
        CommandChirho::RealtimeEpilogueVerifyChirho => {
            let count_chirho =
                realtime_ledger_bound_evidence_chirho::verify_realtime_epilogues_chirho(
                    root_chirho,
                )?;
            println!("verified {count_chirho} realtime epilogue record(s)");
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::args_chirho::realtime_args_chirho::{
        RealtimeCloseArgsChirho, RealtimeEpilogueArgsChirho, RealtimeEventArgsChirho,
        RealtimeOpenAiUsageImportArgsChirho, RealtimeOpenArgsChirho,
        RealtimeProviderUsageArgsChirho, RealtimeSweepArgsChirho, RealtimeTickArgsChirho,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root_chirho() -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cairn-realtime-cli-refusal-{}-{}-{}",
            std::process::id(),
            nanos_chirho,
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn every_realtime_v1_mutation_cli_refuses_before_io_chirho() {
        let root_chirho = temp_root_chirho();
        let commands_chirho = vec![
            CommandChirho::RealtimeOpenChirho(RealtimeOpenArgsChirho {
                session_chirho: "session-chirho".to_string(),
                app_chirho: "app-chirho".to_string(),
                caller_chirho: "user/caller-chirho".to_string(),
                payer_chirho: "user/payer-chirho".to_string(),
                provider_chirho: "provider/realtime-chirho".to_string(),
                max_seconds_chirho: 60,
                token_per_second_chirho: 2,
            }),
            CommandChirho::RealtimeEventChirho(RealtimeEventArgsChirho {
                session_chirho: "session-chirho".to_string(),
                kind_chirho: "user".to_string(),
                payload_chirho: "private@example.com".to_string(),
            }),
            CommandChirho::RealtimeTickChirho(RealtimeTickArgsChirho {
                session_chirho: "session-chirho".to_string(),
            }),
            CommandChirho::RealtimeProviderUsageChirho(RealtimeProviderUsageArgsChirho {
                session_chirho: "session-chirho".to_string(),
                seconds_chirho: 1,
                token_chirho: 2,
                payload_chirho: "private@example.com".to_string(),
            }),
            CommandChirho::RealtimeOpenAiUsageImportChirho(RealtimeOpenAiUsageImportArgsChirho {
                session_chirho: "session-chirho".to_string(),
                provider_session_chirho: "provider-session-chirho".to_string(),
                receipt_file_chirho: root_chirho.join("missing-receipt-chirho.json"),
            }),
            CommandChirho::RealtimeCloseChirho(RealtimeCloseArgsChirho {
                session_chirho: "session-chirho".to_string(),
                transcript_chirho: "private@example.com".to_string(),
                reason_chirho: "closed-chirho".to_string(),
            }),
            CommandChirho::RealtimeSweepChirho(RealtimeSweepArgsChirho {
                stale_after_ms_chirho: 1,
            }),
            CommandChirho::RealtimeEpilogueChirho(RealtimeEpilogueArgsChirho {
                session_chirho: "session-chirho".to_string(),
                dag_chirho: None,
            }),
        ];

        for command_chirho in commands_chirho {
            let result_chirho = handle_realtime_command_chirho(&root_chirho, command_chirho);
            let error_chirho = match result_chirho {
                Err(error_chirho) => error_chirho,
                Ok(_) => panic!("retired realtime mutation command unexpectedly succeeded"),
            };
            assert!(error_chirho.to_string().contains("legacy money road"));
            assert!(error_chirho.to_string().contains("RealtimeSessionChirho"));
            assert!(!root_chirho.exists());
        }
    }
}
