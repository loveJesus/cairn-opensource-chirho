// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Proves the identity auth-attempt log reaches the window view correctly: every decision input is signed, the view
//! decides like today's full scan on real signed logs with a second writer, a sign-in attempt verifies only new
//! records on both the pre-check and the in-lock path, and the full verification and the view agree on every
//! single-byte change to a log.

use super::auth_attempt_window_chirho::AUTH_ATTEMPT_VERIFICATIONS_CHIRHO;
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const LOGIN_CHIRHO: &str = AUTH_ENDPOINT_LOGIN_CHIRHO;
const FAILURE_CHIRHO: IdentityAuthAttemptOutcomeChirho =
    IdentityAuthAttemptOutcomeChirho::FailureChirho;
const SUCCESS_CHIRHO: IdentityAuthAttemptOutcomeChirho =
    IdentityAuthAttemptOutcomeChirho::SuccessChirho;

fn window_root_chirho(name_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-auth-window-{name_chirho}-{}-{}-{}",
        std::process::id(),
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed),
        now_ms_chirho()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

/// Today's decision, as the full-scan code this brick replaced computed it: verify the whole log, load it, and count
/// the key's failures in the window that come after its latest success.
fn full_scan_failures_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    endpoint_chirho: &str,
) -> u64 {
    verify_auth_attempts_chirho(root_chirho).unwrap();
    let records_chirho = load_auth_attempts_chirho(root_chirho).unwrap();
    let principal_hash_chirho = auth_attempt_principal_hash_chirho(principal_chirho);
    let window_start_chirho = now_ms_chirho().saturating_sub(PUBLIC_AUTH_FAILURE_WINDOW_MS_CHIRHO);
    let latest_success_seq_chirho = records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.principal_hash_chirho == principal_hash_chirho
                && record_chirho.endpoint_chirho == endpoint_chirho
                && record_chirho.outcome_chirho == SUCCESS_CHIRHO
        })
        .map(|record_chirho| record_chirho.seq_chirho)
        .max();
    records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.principal_hash_chirho == principal_hash_chirho
                && record_chirho.endpoint_chirho == endpoint_chirho
                && record_chirho.outcome_chirho == FAILURE_CHIRHO
                && record_chirho.at_ms_chirho >= window_start_chirho
                && latest_success_seq_chirho
                    .map(|seq_chirho| record_chirho.seq_chirho > seq_chirho)
                    .unwrap_or(true)
        })
        .count() as u64
}

/// Another writer (an operator command, another serve process): signs and appends under the shared append lock
/// without touching this process's view.
fn foreign_append_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    endpoint_chirho: &str,
    outcome_chirho: IdentityAuthAttemptOutcomeChirho,
) {
    let principal_hash_chirho = auth_attempt_principal_hash_chirho(principal_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(
        root_chirho,
        &auth_attempts_path_chirho(root_chirho),
        |seq_chirho| {
            let mut record_chirho = IdentityAuthAttemptRecordChirho {
                seq_chirho,
                schema_chirho: IDENTITY_AUTH_ATTEMPT_RECORD_SCHEMA_CHIRHO.to_string(),
                principal_hash_chirho: principal_hash_chirho.clone(),
                endpoint_chirho: endpoint_chirho.to_string(),
                outcome_chirho,
                at_ms_chirho: now_ms_chirho(),
                sig_chirho: String::new(),
            };
            let message_chirho = auth_attempt_message_chirho(&record_chirho)?;
            record_chirho.sig_chirho =
                signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
            Ok(record_chirho)
        },
    )
    .unwrap();
}

/// Records verified on this thread while `action_chirho` runs.
fn verifications_during_chirho(action_chirho: impl FnOnce()) -> u64 {
    AUTH_ATTEMPT_VERIFICATIONS_CHIRHO.with(|count_chirho| count_chirho.set(0));
    action_chirho();
    AUTH_ATTEMPT_VERIFICATIONS_CHIRHO.with(|count_chirho| count_chirho.get())
}

/// The view trusts what it verified once, so every field the decision reads must be inside the signature.
#[test]
fn every_decision_input_is_inside_the_signature_chirho() {
    let root_chirho = window_root_chirho("signed-fields");
    let record_chirho =
        append_auth_attempt_chirho(&root_chirho, "alice", LOGIN_CHIRHO, FAILURE_CHIRHO).unwrap();
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(&root_chirho).unwrap();
    verify_auth_attempt_record_chirho(&pubkey_chirho, &record_chirho, 0)
        .expect("control: the record as written verifies");
    type ChangeChirho = fn(&mut IdentityAuthAttemptRecordChirho);
    let changes_chirho: [(&str, ChangeChirho); 5] = [
        ("seq", |record_chirho| record_chirho.seq_chirho += 1),
        ("principal hash", |record_chirho| {
            record_chirho.principal_hash_chirho = auth_attempt_principal_hash_chirho("mallory")
        }),
        ("endpoint", |record_chirho| {
            record_chirho.endpoint_chirho = AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO.to_string()
        }),
        ("outcome", |record_chirho| {
            record_chirho.outcome_chirho = SUCCESS_CHIRHO
        }),
        ("at_ms", |record_chirho| record_chirho.at_ms_chirho += 1),
    ];
    for (field_chirho, change_chirho) in changes_chirho {
        let mut changed_chirho = record_chirho.clone();
        change_chirho(&mut changed_chirho);
        // The changed seq is passed as expected and every value keeps its valid shape, so only the signature can
        // refuse.
        let error_chirho = verify_auth_attempt_record_chirho(
            &pubkey_chirho,
            &changed_chirho,
            changed_chirho.seq_chirho,
        )
        .expect_err("a changed decision input must not verify")
        .to_string();
        assert!(
            error_chirho.contains("signature invalid"),
            "changing {field_chirho} must break the signature, got: {error_chirho}"
        );
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Real signed records from this process and from a second writer, every key and endpoint: the view's count and the
/// limiter's decision equal today's full scan at every check.
#[test]
fn the_view_decides_like_todays_full_scan_on_real_signed_logs_chirho() {
    let root_chirho = window_root_chirho("equivalence");
    let principals_chirho = ["alice", "bob", "carol"];
    let endpoints_chirho = [
        AUTH_ENDPOINT_LOGIN_CHIRHO,
        AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO,
        AUTH_ENDPOINT_REGISTER_CHIRHO,
    ];
    let mut state_chirho = 0x2545_F491_4F6C_DD1Du64;
    let mut next_chirho = move || {
        state_chirho ^= state_chirho << 13;
        state_chirho ^= state_chirho >> 7;
        state_chirho ^= state_chirho << 17;
        state_chirho
    };
    let mut checks_chirho = 0u64;
    for step_chirho in 0..150 {
        let principal_chirho = principals_chirho[(next_chirho() % 3) as usize];
        let endpoint_chirho = endpoints_chirho[(next_chirho() % 3) as usize];
        let outcome_chirho = if next_chirho() % 4 == 0 {
            SUCCESS_CHIRHO
        } else {
            FAILURE_CHIRHO
        };
        match next_chirho() % 3 {
            0 => {
                append_auth_attempt_chirho(
                    &root_chirho,
                    principal_chirho,
                    endpoint_chirho,
                    outcome_chirho,
                )
                .unwrap();
            }
            1 => foreign_append_chirho(
                &root_chirho,
                principal_chirho,
                endpoint_chirho,
                outcome_chirho,
            ),
            _ => {
                for principal_chirho in principals_chirho {
                    for endpoint_chirho in endpoints_chirho {
                        let expected_chirho = full_scan_failures_chirho(
                            &root_chirho,
                            principal_chirho,
                            endpoint_chirho,
                        );
                        let principal_hash_chirho =
                            auth_attempt_principal_hash_chirho(principal_chirho);
                        assert_eq!(
                            recent_auth_failures_chirho(
                                &root_chirho,
                                &principal_hash_chirho,
                                endpoint_chirho
                            )
                            .unwrap(),
                            expected_chirho,
                            "step {step_chirho}: {principal_chirho}/{endpoint_chirho}"
                        );
                        let allowed_chirho = ensure_public_auth_attempt_allowed_chirho(
                            &root_chirho,
                            principal_chirho,
                            endpoint_chirho,
                        );
                        assert_eq!(
                            allowed_chirho.is_ok(),
                            expected_chirho < PUBLIC_AUTH_MAX_FAILURES_CHIRHO,
                            "step {step_chirho}: the limiter's decision for {principal_chirho}/{endpoint_chirho}"
                        );
                        checks_chirho += 1;
                    }
                }
            }
        }
    }
    assert!(
        checks_chirho > 200,
        "control: the history must exercise the checks, ran {checks_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The wiring's scaling guard: after the first check, each sign-in attempt's pre-check verifies only the one record
/// the previous attempt appended, and its in-lock check verifies none. A second writer's records arrive as a delta.
#[test]
fn a_sign_in_attempt_verifies_only_new_records_on_both_paths_chirho() {
    let root_chirho = window_root_chirho("scaling");
    for warm_chirho in 0..300 {
        foreign_append_chirho(
            &root_chirho,
            &format!("warm-{warm_chirho}"),
            LOGIN_CHIRHO,
            FAILURE_CHIRHO,
        );
    }
    let first_chirho = verifications_during_chirho(|| {
        ensure_public_auth_attempt_allowed_chirho(&root_chirho, "first", LOGIN_CHIRHO).unwrap()
    });
    assert_eq!(
        first_chirho, 300,
        "control: the first check verifies the whole log once"
    );
    for round_chirho in 0..20u64 {
        let principal_chirho = format!("attempt-{round_chirho}");
        let pre_check_chirho = verifications_during_chirho(|| {
            ensure_public_auth_attempt_allowed_chirho(&root_chirho, &principal_chirho, LOGIN_CHIRHO)
                .unwrap()
        });
        assert_eq!(
            pre_check_chirho,
            u64::from(round_chirho > 0),
            "round {round_chirho}: the pre-check verified history again"
        );
        let in_lock_chirho = verifications_during_chirho(|| {
            append_auth_attempt_chirho(
                &root_chirho,
                &principal_chirho,
                LOGIN_CHIRHO,
                FAILURE_CHIRHO,
            )
            .unwrap();
        });
        assert_eq!(
            in_lock_chirho, 0,
            "round {round_chirho}: the in-lock check verified records it had already seen"
        );
    }
    foreign_append_chirho(&root_chirho, "other-writer", LOGIN_CHIRHO, FAILURE_CHIRHO);
    foreign_append_chirho(&root_chirho, "other-writer", LOGIN_CHIRHO, FAILURE_CHIRHO);
    let after_chirho = verifications_during_chirho(|| {
        ensure_public_auth_attempt_allowed_chirho(&root_chirho, "after-foreign", LOGIN_CHIRHO)
            .unwrap()
    });
    assert_eq!(
        after_chirho, 3,
        "the last in-process record and the other writer's two, each verified once"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The view and the full verification share one parser and one verifier (PFE #1257 A4): on every single-byte change
/// to a real log they accept or refuse alike, with the same count or the same error.
#[test]
fn the_full_verification_and_the_view_agree_on_every_single_byte_change_chirho() {
    let root_chirho = window_root_chirho("agreement");
    for n_chirho in 0..12u64 {
        let outcome_chirho = if n_chirho % 4 == 0 {
            SUCCESS_CHIRHO
        } else {
            FAILURE_CHIRHO
        };
        append_auth_attempt_chirho(
            &root_chirho,
            &format!("p{}", n_chirho % 3),
            LOGIN_CHIRHO,
            outcome_chirho,
        )
        .unwrap();
    }
    let path_chirho = auth_attempts_path_chirho(&root_chirho);
    let original_chirho = std::fs::read(&path_chirho).unwrap();
    // Bring the view up to the whole file first. The last append's in-lock check ran before its own record was
    // written, so without this the first change would look like an append plus an edit to an older record: the
    // stated threat boundary (pinned in the crate's boundary arm), not a fresh fold. Every change below keeps the
    // length, so each one verifies from scratch, as PFE #1257 A4 asks.
    assert_eq!(
        verify_auth_attempts_current_chirho(&root_chirho).unwrap(),
        12
    );
    let alphabet_chirho = b"0123456789abcdefSF\"{}:, xz";
    let mut state_chirho = 0x9E37_79B9_7F4A_7C15u64;
    let mut next_chirho = move || {
        state_chirho ^= state_chirho << 13;
        state_chirho ^= state_chirho >> 7;
        state_chirho ^= state_chirho << 17;
        state_chirho
    };
    let (mut trials_chirho, mut refusals_chirho) = (0u64, 0u64);
    for trial_chirho in 0..80u64 {
        let mut bytes_chirho = original_chirho.clone();
        // Never the final newline: a torn final line is the one stated difference (the view waits for it).
        let at_chirho = (next_chirho() % (bytes_chirho.len() as u64 - 1)) as usize;
        let replacement_chirho =
            alphabet_chirho[(next_chirho() % alphabet_chirho.len() as u64) as usize];
        if bytes_chirho[at_chirho] == replacement_chirho {
            continue;
        }
        bytes_chirho[at_chirho] = replacement_chirho;
        std::fs::write(&path_chirho, &bytes_chirho).unwrap();
        // A distinct mtime, so the change shows on filesystems with coarse timestamps too.
        std::fs::File::options()
            .write(true)
            .open(&path_chirho)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(trial_chirho + 1))
            .unwrap();
        let full_chirho = verify_auth_attempts_chirho(&root_chirho)
            .map(|count_chirho| count_chirho as u64)
            .map_err(|error_chirho| error_chirho.to_string());
        let view_chirho = verify_auth_attempts_current_chirho(&root_chirho)
            .map_err(|error_chirho| error_chirho.to_string());
        assert_eq!(
            view_chirho, full_chirho,
            "trial {trial_chirho}: byte {at_chirho} became {:?}",
            replacement_chirho as char
        );
        trials_chirho += 1;
        refusals_chirho += u64::from(full_chirho.is_err());
    }
    assert!(
        trials_chirho >= 60 && refusals_chirho * 10 >= trials_chirho * 8,
        "control: most single-byte changes must be refused ({refusals_chirho} of {trials_chirho})"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The serve runtime warms the view at startup (brick 2b): afterwards the first sign-in check verifies nothing,
/// which also proves the warm-up derives the same key the checks do, and a root with no log stays untouched,
/// because startup stays write-free.
#[test]
fn the_startup_warm_up_takes_the_first_load_off_the_first_sign_in_chirho() {
    let root_chirho = window_root_chirho("warm");
    for n_chirho in 0..50 {
        foreign_append_chirho(
            &root_chirho,
            &format!("warm-{n_chirho}"),
            LOGIN_CHIRHO,
            FAILURE_CHIRHO,
        );
    }
    let warmed_chirho = verifications_during_chirho(|| {
        assert_eq!(warm_auth_attempt_view_chirho(&root_chirho).unwrap(), 50);
    });
    assert_eq!(
        warmed_chirho, 50,
        "control: the warm-up verifies the whole log once"
    );
    let first_check_chirho = verifications_during_chirho(|| {
        ensure_public_auth_attempt_allowed_chirho(&root_chirho, "first-visitor", LOGIN_CHIRHO)
            .unwrap()
    });
    assert_eq!(
        first_check_chirho, 0,
        "the first sign-in after a warm-up must not load the log again"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);

    let empty_root_chirho = window_root_chirho("warm-empty");
    assert_eq!(
        warm_auth_attempt_view_chirho(&empty_root_chirho).unwrap(),
        0
    );
    assert_eq!(
        std::fs::read_dir(&empty_root_chirho).unwrap().count(),
        0,
        "the warm-up wrote to a root it found empty"
    );
    let _ = std::fs::remove_dir_all(&empty_root_chirho);
}
