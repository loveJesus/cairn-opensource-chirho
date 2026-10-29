// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The oauth verify commands read K4's connection stores: a connection log that does not verify fails `oauth-verify`
//! as well as `oauth-connection-verify`, while a root without one verifies under both.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT_CHIRHO: AtomicU64 = AtomicU64::new(0);

fn fresh_root_chirho(label_chirho: &str) -> std::path::PathBuf {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-k4-oauth-verify-{label_chirho}-{}-{}-chirho",
        std::process::id(),
        NEXT_ROOT_CHIRHO.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root_chirho).unwrap();
    root_chirho
}

/// EACH CONNECTION LOG FAILS BOTH VERIFY COMMANDS WHEN IT DOES NOT VERIFY: per log, the empty root verifies under both
/// commands (the control), then an unparsable row in that one log fails both.
#[test]
fn both_oauth_verify_commands_read_the_connection_logs_chirho() {
    for log_chirho in [
        "oauth-connection-clients-chirho.jsonl",
        "connection-tokens-chirho.jsonl",
        "connection-token-uses-chirho.jsonl",
    ] {
        let root_chirho = fresh_root_chirho("faulted");
        let run_chirho = |command_chirho: CommandChirho| {
            handle_identity_command_chirho(&root_chirho, command_chirho)
        };
        assert!(run_chirho(CommandChirho::OauthVerifyChirho).is_ok());
        assert!(run_chirho(CommandChirho::OauthConnectionVerifyChirho).is_ok());
        std::fs::write(root_chirho.join(log_chirho), "{\"not\": \"a row\"}\n").unwrap();
        assert!(
            run_chirho(CommandChirho::OauthVerifyChirho).is_err(),
            "oauth-verify passed over a faulted {log_chirho}"
        );
        assert!(
            run_chirho(CommandChirho::OauthConnectionVerifyChirho).is_err(),
            "oauth-connection-verify passed over a faulted {log_chirho}"
        );
        std::fs::remove_dir_all(&root_chirho).unwrap();
    }
}
