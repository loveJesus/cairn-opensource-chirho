// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Brick 4b-1's arms for the session road: the session index and the revocation set answer as today's full scans,
//! refuse what today's verifiers refuse with the same identity, and the revocation door writes one record per session.

use super::*;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-session-views-{label_chirho}-{}-{n_chirho}-{}",
        std::process::id(),
        now_ms_chirho()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn user_chirho(root_chirho: &Path) -> String {
    register_identity_chirho(root_chirho, PrincipalKindChirho::UserChirho)
        .unwrap()
        .principal_chirho
}

fn pubkey_chirho(root_chirho: &Path) -> String {
    signer_chirho::pubkey_hex_chirho(root_chirho).unwrap()
}

fn bump_generation_chirho(root_chirho: &Path, principal_chirho: &str) {
    let mut key_record_chirho =
        load_identity_key_record_chirho(root_chirho, principal_chirho).unwrap();
    key_record_chirho.credential_generation_chirho += 1;
    write_identity_key_record_chirho(root_chirho, &key_record_chirho).unwrap();
}

fn revocation_lines_chirho(root_chirho: &Path) -> usize {
    std::fs::read_to_string(session_revocations_path_chirho(root_chirho))
        .unwrap_or_default()
        .lines()
        .filter(|line_chirho| parse_session_revocation_line_chirho(line_chirho).is_ok())
        .count()
}

struct RngChirho(u64);

impl RngChirho {
    fn below_chirho(&mut self, bound_chirho: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % bound_chirho as u64) as usize
    }
}

/// What today's check decided, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
enum TodayChirho {
    LiveChirho(IdentitySessionChirho),
    NoSessionChirho,
    ExpiredChirho,
    StaleChirho,
    RevokedChirho,
}

/// The two logs as today's checks read them, each verified once per step by today's full verifier. Every check in a step
/// reads the same bytes, so hoisting the verification out of the per-check loop changes no answer.
struct TodaysLogsChirho {
    sessions_chirho: Vec<IdentitySessionChirho>,
    revocations_chirho: Vec<IdentitySessionRevocationRecordChirho>,
}

fn todays_logs_chirho(root_chirho: &Path) -> TodaysLogsChirho {
    TodaysLogsChirho {
        sessions_chirho: load_verified_sessions_chirho(root_chirho).unwrap(),
        revocations_chirho: load_verified_session_revocations_chirho(root_chirho).unwrap(),
    }
}

/// Today's liveness of a session it found: the expiry, the credential generation, then today's revocation match.
fn todays_liveness_chirho(
    root_chirho: &Path,
    logs_chirho: &TodaysLogsChirho,
    session_chirho: Option<&IdentitySessionChirho>,
    now_ms_chirho: u64,
) -> TodayChirho {
    let Some(session_chirho) = session_chirho else {
        return TodayChirho::NoSessionChirho;
    };
    if session_chirho.expires_ms_chirho < now_ms_chirho {
        return TodayChirho::ExpiredChirho;
    }
    let key_record_chirho =
        load_identity_key_record_chirho(root_chirho, &session_chirho.principal_chirho).unwrap();
    if session_chirho.credential_generation_chirho != key_record_chirho.credential_generation_chirho
    {
        return TodayChirho::StaleChirho;
    }
    if logs_chirho
        .revocations_chirho
        .iter()
        .any(|revocation_chirho| {
            revocation_chirho.principal_chirho == session_chirho.principal_chirho
                && revocation_chirho.session_seq_chirho == session_chirho.seq_chirho
                && revocation_chirho.token_hash_chirho == session_chirho.token_hash_chirho
        })
    {
        return TodayChirho::RevokedChirho;
    }
    TodayChirho::LiveChirho(session_chirho.clone())
}

/// Today's cookie check, the scan the session index replaced: newest first for the principal and token hash.
fn todays_cookie_check_chirho(
    root_chirho: &Path,
    logs_chirho: &TodaysLogsChirho,
    principal_chirho: &str,
    token_chirho: &str,
    now_ms_chirho: u64,
) -> TodayChirho {
    let expected_chirho = token_hash_chirho(token_chirho);
    let session_chirho = logs_chirho
        .sessions_chirho
        .iter()
        .rev()
        .find(|session_chirho| {
            session_chirho.principal_chirho == principal_chirho
                && constant_time_string_eq_chirho(
                    &session_chirho.token_hash_chirho,
                    &expected_chirho,
                )
        });
    todays_liveness_chirho(root_chirho, logs_chirho, session_chirho, now_ms_chirho)
}

/// Today's answer to the bearer road's question: the session at this principal and seq, then its liveness.
fn todays_key_session_check_chirho(
    root_chirho: &Path,
    logs_chirho: &TodaysLogsChirho,
    principal_chirho: &str,
    session_seq_chirho: u64,
    now_ms_chirho: u64,
) -> TodayChirho {
    let session_chirho = logs_chirho.sessions_chirho.iter().find(|session_chirho| {
        session_chirho.seq_chirho == session_seq_chirho
            && session_chirho.principal_chirho == principal_chirho
    });
    todays_liveness_chirho(root_chirho, logs_chirho, session_chirho, now_ms_chirho)
}

fn outcome_index_chirho(today_chirho: &TodayChirho) -> usize {
    match today_chirho {
        TodayChirho::LiveChirho(_) => 0,
        TodayChirho::NoSessionChirho => 1,
        TodayChirho::ExpiredChirho => 2,
        TodayChirho::StaleChirho => 3,
        TodayChirho::RevokedChirho => 4,
    }
}

/// THE VIEWS' EQUIVALENCE: a random run of sign-ins, revocations (by token and by seq, repeats included) and credential
/// generation bumps across three principals is answered by the session index and the revocation set exactly as today's
/// full scans answer it. Every session issued so far is checked after every step, at its issue, at its exact expiry and
/// just past it, on the cookie road and as the bearer road asks it (by principal and seq), with a wrong-principal probe
/// and an unknown token beside them; revocation membership and the seq lookup are compared too. The controls prove every
/// outcome was exercised (live, no session, expired, stale, revoked) on both questions, and the logs the door wrote are
/// ones today's verifiers accept.
///
/// MIGRATION PATH: a live answer where today refuses is a session, or a key, that should have ended; a refusal where
/// today admits signs an owner out.
#[test]
fn the_views_answer_as_todays_full_scans_over_a_random_history_chirho() {
    let root_chirho = tmp_root_chirho("equivalence");
    let principals_chirho: Vec<String> = (0..3).map(|_| user_chirho(&root_chirho)).collect();
    let pubkey_chirho = pubkey_chirho(&root_chirho);
    let mut rng_chirho = RngChirho(0x5eed_4b01_cafe_f00d);
    let mut issued_chirho: Vec<IdentityLoginResultChirho> = Vec::new();
    let mut cookie_seen_chirho = [0usize; 5];
    let mut key_seen_chirho = [0usize; 5];
    for step_chirho in 0..48 {
        let op_chirho = rng_chirho.below_chirho(8);
        if op_chirho <= 3 || issued_chirho.is_empty() {
            let principal_chirho = &principals_chirho[rng_chirho.below_chirho(3)];
            issued_chirho.push(login_identity_chirho(&root_chirho, principal_chirho).unwrap());
        } else if op_chirho <= 5 {
            let login_chirho = &issued_chirho[rng_chirho.below_chirho(issued_chirho.len())];
            let principal_chirho = &login_chirho.session_chirho.principal_chirho;
            if op_chirho == 4 {
                revoke_session_token_chirho(
                    &root_chirho,
                    principal_chirho,
                    &login_chirho.token_chirho,
                    "operator-chirho",
                    "equivalence arm",
                )
                .unwrap();
            } else {
                revoke_session_by_seq_chirho(
                    &root_chirho,
                    principal_chirho,
                    login_chirho.session_chirho.seq_chirho,
                    "operator-chirho",
                    "equivalence arm",
                )
                .unwrap();
            }
        } else if op_chirho == 6 {
            bump_generation_chirho(&root_chirho, &principals_chirho[rng_chirho.below_chirho(3)]);
        }
        let logs_chirho = todays_logs_chirho(&root_chirho);
        for (n_chirho, login_chirho) in issued_chirho.iter().enumerate() {
            let session_chirho = &login_chirho.session_chirho;
            let wrong_principal_chirho = &principals_chirho[(principals_chirho
                .iter()
                .position(|p_chirho| *p_chirho == session_chirho.principal_chirho)
                .unwrap()
                + 1)
                % 3];
            let probes_chirho = [
                (
                    session_chirho.principal_chirho.as_str(),
                    login_chirho.token_chirho.as_str(),
                ),
                (
                    wrong_principal_chirho.as_str(),
                    login_chirho.token_chirho.as_str(),
                ),
                (
                    session_chirho.principal_chirho.as_str(),
                    "not-a-session-token-chirho",
                ),
            ];
            for now_ms_chirho in [
                session_chirho.issued_ms_chirho,
                session_chirho.expires_ms_chirho,
                session_chirho.expires_ms_chirho + 1,
            ] {
                for (principal_chirho, token_chirho) in probes_chirho {
                    let today_chirho = todays_cookie_check_chirho(
                        &root_chirho,
                        &logs_chirho,
                        principal_chirho,
                        token_chirho,
                        now_ms_chirho,
                    );
                    let view_chirho = validate_session_token_at_chirho(
                        &root_chirho,
                        principal_chirho,
                        token_chirho,
                        now_ms_chirho,
                    )
                    .unwrap();
                    let expected_chirho = match &today_chirho {
                        TodayChirho::LiveChirho(live_chirho) => Some(live_chirho.clone()),
                        _ => None,
                    };
                    assert_eq!(
                        view_chirho, expected_chirho,
                        "cookie: step {step_chirho}, session {n_chirho}, today {today_chirho:?}"
                    );
                    cookie_seen_chirho[outcome_index_chirho(&today_chirho)] += 1;
                }
                let today_key_chirho = todays_key_session_check_chirho(
                    &root_chirho,
                    &logs_chirho,
                    &session_chirho.principal_chirho,
                    session_chirho.seq_chirho,
                    now_ms_chirho,
                );
                assert_eq!(
                    key_session_live_chirho(
                        &root_chirho,
                        &pubkey_chirho,
                        &session_chirho.principal_chirho,
                        session_chirho.seq_chirho,
                        now_ms_chirho,
                    )
                    .unwrap(),
                    matches!(today_key_chirho, TodayChirho::LiveChirho(_)),
                    "key session: step {step_chirho}, session {n_chirho}, today {today_key_chirho:?}"
                );
                key_seen_chirho[outcome_index_chirho(&today_key_chirho)] += 1;
            }
            // The bearer road's question for a seq that is another principal's: no session, today and now.
            let today_wrong_chirho = todays_key_session_check_chirho(
                &root_chirho,
                &logs_chirho,
                wrong_principal_chirho,
                session_chirho.seq_chirho,
                session_chirho.issued_ms_chirho,
            );
            assert_eq!(today_wrong_chirho, TodayChirho::NoSessionChirho);
            assert!(!key_session_live_chirho(
                &root_chirho,
                &pubkey_chirho,
                wrong_principal_chirho,
                session_chirho.seq_chirho,
                session_chirho.issued_ms_chirho,
            )
            .unwrap());
            key_seen_chirho[outcome_index_chirho(&today_wrong_chirho)] += 1;
            let revoked_today_chirho =
                logs_chirho
                    .revocations_chirho
                    .iter()
                    .any(|revocation_chirho| {
                        revocation_chirho.principal_chirho == session_chirho.principal_chirho
                            && revocation_chirho.session_seq_chirho == session_chirho.seq_chirho
                            && revocation_chirho.token_hash_chirho
                                == session_chirho.token_hash_chirho
                    });
            assert_eq!(
                session_is_revoked_chirho(&root_chirho, &pubkey_chirho, session_chirho).unwrap(),
                revoked_today_chirho,
                "revocation membership: step {step_chirho}, session {n_chirho}"
            );
            assert_eq!(
                find_verified_session_by_seq_chirho(
                    &root_chirho,
                    &session_chirho.principal_chirho,
                    session_chirho.seq_chirho,
                )
                .unwrap()
                .as_ref(),
                Some(session_chirho),
                "seq lookup: step {step_chirho}, session {n_chirho}"
            );
        }
    }
    for (label_chirho, seen_chirho) in [
        ("cookie", cookie_seen_chirho),
        ("key session", key_seen_chirho),
    ] {
        assert!(
            seen_chirho.iter().all(|count_chirho| *count_chirho > 0),
            "{label_chirho}: every outcome (live, no session, expired, stale, revoked) must be exercised: {seen_chirho:?}"
        );
    }
    assert_eq!(
        verify_sessions_chirho(&root_chirho).unwrap(),
        issued_chirho.len()
    );
    assert!(verify_session_revocations_chirho(&root_chirho).unwrap() > 0);
}

fn resigned_session_chirho(
    root_chirho: &Path,
    mut session_chirho: IdentitySessionChirho,
) -> IdentitySessionChirho {
    let key_record_chirho =
        load_identity_key_record_chirho(root_chirho, &session_chirho.principal_chirho).unwrap();
    let signing_key_chirho = signing_key_from_identity_key_chirho(&key_record_chirho).unwrap();
    session_chirho.proof_chirho = hex_encode_chirho(
        &signing_key_chirho
            .sign(&session_proof_message_chirho(&session_chirho).unwrap())
            .to_bytes(),
    );
    session_chirho.sig_chirho.clear();
    session_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &session_message_chirho(&session_chirho).unwrap(),
    )
    .unwrap();
    session_chirho
}

fn resigned_revocation_chirho(
    root_chirho: &Path,
    mut revocation_chirho: IdentitySessionRevocationRecordChirho,
) -> IdentitySessionRevocationRecordChirho {
    revocation_chirho.sig_chirho.clear();
    revocation_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &session_revocation_message_chirho(&revocation_chirho).unwrap(),
    )
    .unwrap();
    revocation_chirho
}

fn append_line_chirho<T: Serialize>(path_chirho: &Path, record_chirho: &T) {
    let mut file_chirho = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path_chirho)
        .unwrap();
    writeln!(
        file_chirho,
        "{}",
        serde_json::to_string(record_chirho).unwrap()
    )
    .unwrap();
}

/// A tampered record, built from a root's newest real records: which log it goes in, and the record itself.
enum TamperChirho {
    SessionChirho(IdentitySessionChirho),
    RevocationChirho(IdentitySessionRevocationRecordChirho),
}

/// The tampers, each a record today's full verifier refuses for exactly one reason. `live_chirho` is the session the
/// probe checks, so the revocation set is consulted; `revoked_chirho` is a real revocation of another session.
fn tampers_chirho(
    root_chirho: &Path,
    live_chirho: &IdentitySessionChirho,
    revoked_chirho: &IdentitySessionRevocationRecordChirho,
) -> Vec<(&'static str, TamperChirho)> {
    let next_session_chirho = load_sessions_chirho(root_chirho).unwrap().len() as u64;
    let next_revocation_chirho = load_session_revocations_chirho(root_chirho).unwrap().len() as u64;
    let session_at_chirho = |seq_chirho: u64| IdentitySessionChirho {
        seq_chirho,
        token_hash_chirho: token_hash_chirho(&format!("tamper-{seq_chirho}")),
        ..live_chirho.clone()
    };
    let mut bad_signature_chirho =
        resigned_session_chirho(root_chirho, session_at_chirho(next_session_chirho));
    bad_signature_chirho.sig_chirho = "00".repeat(64);
    let mut bad_proof_chirho =
        resigned_session_chirho(root_chirho, session_at_chirho(next_session_chirho));
    bad_proof_chirho.expires_ms_chirho += 1;
    let mut unknown_principal_chirho = session_at_chirho(next_session_chirho);
    unknown_principal_chirho.principal_chirho = "user-chirho-nobody".to_string();
    let mut bad_revocation_signature_chirho = revoked_chirho.clone();
    bad_revocation_signature_chirho.seq_chirho = next_revocation_chirho;
    bad_revocation_signature_chirho.sig_chirho = "00".repeat(64);
    let mut missing_target_chirho = revoked_chirho.clone();
    missing_target_chirho.seq_chirho = next_revocation_chirho;
    missing_target_chirho.session_seq_chirho = next_session_chirho + 7;
    let mut predates_chirho = revoked_chirho.clone();
    predates_chirho.seq_chirho = next_revocation_chirho;
    predates_chirho.at_ms_chirho = 1;
    vec![
        (
            "session seq gap",
            TamperChirho::SessionChirho(resigned_session_chirho(
                root_chirho,
                session_at_chirho(next_session_chirho + 1),
            )),
        ),
        (
            "session key proof",
            TamperChirho::SessionChirho(bad_proof_chirho),
        ),
        (
            "session signature",
            TamperChirho::SessionChirho(bad_signature_chirho),
        ),
        (
            "session principal",
            TamperChirho::SessionChirho(unknown_principal_chirho),
        ),
        (
            "revocation seq gap",
            TamperChirho::RevocationChirho(resigned_revocation_chirho(root_chirho, {
                let mut gap_chirho = revoked_chirho.clone();
                gap_chirho.seq_chirho = next_revocation_chirho + 1;
                gap_chirho
            })),
        ),
        (
            "revocation signature",
            TamperChirho::RevocationChirho(bad_revocation_signature_chirho),
        ),
        (
            "revocation target",
            TamperChirho::RevocationChirho(resigned_revocation_chirho(
                root_chirho,
                missing_target_chirho,
            )),
        ),
        (
            "revocation predates",
            TamperChirho::RevocationChirho(resigned_revocation_chirho(
                root_chirho,
                predates_chirho,
            )),
        ),
    ]
}

/// A copy of `root_chirho` at a new path: its views have never been built, so its first check is a full pass.
fn copied_root_chirho(root_chirho: &Path) -> PathBuf {
    fn copy_dir_chirho(from_chirho: &Path, to_chirho: &Path) {
        std::fs::create_dir_all(to_chirho).unwrap();
        for entry_chirho in std::fs::read_dir(from_chirho).unwrap() {
            let entry_chirho = entry_chirho.unwrap();
            let target_chirho = to_chirho.join(entry_chirho.file_name());
            if entry_chirho.file_type().unwrap().is_dir() {
                copy_dir_chirho(&entry_chirho.path(), &target_chirho);
            } else {
                std::fs::copy(entry_chirho.path(), &target_chirho).unwrap();
            }
        }
    }
    let copy_chirho = tmp_root_chirho("copy");
    copy_dir_chirho(root_chirho, &copy_chirho);
    copy_chirho
}

const TAMPERS_CHIRHO: usize = 8;

/// THE FOLDS REFUSE WHAT TODAY'S VERIFIERS REFUSE, WITH TODAY'S IDENTITY: each tamper (a seq gap, a bad key proof, a bad
/// signature, an unknown principal; a revocation's seq gap, signature, missing target, and a time before its session)
/// makes the cookie check refuse with the error today's full verifier gives for the same log. Each runs twice: appended
/// after the views are warm (the incremental fold), and in a copied root whose views were never built (the full pass).
/// The controls: before the tamper, the warm check and a never-built copy's first check both answer the live session.
///
/// MIGRATION PATH: an answer instead of a refusal means a fold skipped a check; a refusal with another identity means
/// the fold's checks ran out of today's order.
#[test]
fn each_fold_refuses_a_tamper_with_todays_identity_chirho() {
    for incremental_chirho in [true, false] {
        for which_chirho in 0..TAMPERS_CHIRHO {
            let root_chirho = tmp_root_chirho("tamper");
            let principal_chirho = user_chirho(&root_chirho);
            let other_chirho = login_identity_chirho(&root_chirho, &principal_chirho).unwrap();
            let revoked_chirho = revoke_session_token_chirho(
                &root_chirho,
                &principal_chirho,
                &other_chirho.token_chirho,
                "operator-chirho",
                "tamper arm",
            )
            .unwrap();
            let live_chirho = login_identity_chirho(&root_chirho, &principal_chirho).unwrap();
            let check_chirho = |root_chirho: &Path| {
                validate_session_token_chirho(
                    root_chirho,
                    &principal_chirho,
                    &live_chirho.token_chirho,
                )
            };
            let control_root_chirho = if incremental_chirho {
                root_chirho.clone()
            } else {
                copied_root_chirho(&root_chirho)
            };
            assert_eq!(
                check_chirho(&control_root_chirho).unwrap(),
                Some(live_chirho.session_chirho.clone()),
                "the control: before the tamper the check answers"
            );
            let mut tampers_chirho =
                tampers_chirho(&root_chirho, &live_chirho.session_chirho, &revoked_chirho);
            assert_eq!(tampers_chirho.len(), TAMPERS_CHIRHO);
            let (label_chirho, tamper_chirho) = tampers_chirho.swap_remove(which_chirho);
            let todays_error_chirho = match tamper_chirho {
                TamperChirho::SessionChirho(session_chirho) => {
                    append_line_chirho(&sessions_path_chirho(&root_chirho), &session_chirho);
                    load_verified_sessions_chirho(&root_chirho).unwrap_err()
                }
                TamperChirho::RevocationChirho(revocation_chirho) => {
                    append_line_chirho(
                        &session_revocations_path_chirho(&root_chirho),
                        &revocation_chirho,
                    );
                    load_verified_session_revocations_chirho(&root_chirho).unwrap_err()
                }
            };
            let probed_root_chirho = if incremental_chirho {
                root_chirho.clone()
            } else {
                copied_root_chirho(&root_chirho)
            };
            let refusal_chirho = check_chirho(&probed_root_chirho).unwrap_err();
            assert!(
                format!("{refusal_chirho:#}").contains(&format!("{todays_error_chirho:#}")),
                "{label_chirho} (incremental: {incremental_chirho}): the view refused with {refusal_chirho:#}, \
                 today refuses with {todays_error_chirho:#}"
            );
        }
    }
}

/// Every file under `root_chirho`, with its length: what the warm-up must leave exactly as it found it.
fn files_chirho(root_chirho: &Path) -> std::collections::BTreeMap<PathBuf, u64> {
    let mut files_chirho = std::collections::BTreeMap::new();
    let mut pending_chirho = vec![root_chirho.to_path_buf()];
    while let Some(dir_chirho) = pending_chirho.pop() {
        for entry_chirho in std::fs::read_dir(&dir_chirho).unwrap() {
            let entry_chirho = entry_chirho.unwrap();
            if entry_chirho.file_type().unwrap().is_dir() {
                pending_chirho.push(entry_chirho.path());
            } else {
                files_chirho.insert(entry_chirho.path(), entry_chirho.metadata().unwrap().len());
            }
        }
    }
    files_chirho
}

/// THE WARM-UP BUILDS THE VIEWS THE REQUESTS READ, AND WRITES NOTHING. After `warm_session_views_chirho`, a cookie check
/// parses no session record and no revocation record on this thread, so the warm-up keyed its views with the very key
/// the requests derive. On a root with no session log it does nothing, and on a root whose private key is gone it
/// refuses; in every case it creates and changes no file, so it never mints a key. The control: the same check on a copy
/// nobody warmed does parse records.
///
/// MIGRATION PATH: parses after the warm-up mean it built views under another verifier id, so the first request
/// verifies everything again; a new file means the warm-up created a key.
#[test]
fn the_warm_up_builds_the_views_requests_read_and_writes_nothing_chirho() {
    let root_chirho = tmp_root_chirho("warm-source");
    let principal_chirho = user_chirho(&root_chirho);
    let revoked_chirho = login_identity_chirho(&root_chirho, &principal_chirho).unwrap();
    revoke_session_token_chirho(
        &root_chirho,
        &principal_chirho,
        &revoked_chirho.token_chirho,
        "operator-chirho",
        "warm-up arm",
    )
    .unwrap();
    let live_chirho = login_identity_chirho(&root_chirho, &principal_chirho).unwrap();
    let check_chirho = |root_chirho: &Path| {
        let before_chirho = session_read_metrics_chirho::parses_chirho();
        assert!(validate_session_token_chirho(
            root_chirho,
            &principal_chirho,
            &live_chirho.token_chirho
        )
        .unwrap()
        .is_some());
        let after_chirho = session_read_metrics_chirho::parses_chirho();
        (
            after_chirho.0 - before_chirho.0,
            after_chirho.1 - before_chirho.1,
        )
    };

    let unwarmed_chirho = copied_root_chirho(&root_chirho);
    let (sessions_chirho, revocations_chirho) = check_chirho(&unwarmed_chirho);
    assert!(
        sessions_chirho > 0 && revocations_chirho > 0,
        "the control: a first check on a copy nobody warmed parses both logs"
    );

    let warmed_chirho = copied_root_chirho(&root_chirho);
    let files_before_chirho = files_chirho(&warmed_chirho);
    warm_session_views_chirho(&warmed_chirho).unwrap();
    assert_eq!(
        files_chirho(&warmed_chirho),
        files_before_chirho,
        "the warm-up writes nothing"
    );
    assert_eq!(
        check_chirho(&warmed_chirho),
        (0, 0),
        "the first check after the warm-up parses nothing"
    );

    let empty_chirho = tmp_root_chirho("warm-empty");
    warm_session_views_chirho(&empty_chirho).unwrap();
    assert!(
        files_chirho(&empty_chirho).is_empty(),
        "a root with no session log gets no key"
    );

    let keyless_chirho = copied_root_chirho(&root_chirho);
    std::fs::remove_file(keyless_chirho.join("signing-key-chirho.bin")).unwrap();
    let keyless_files_chirho = files_chirho(&keyless_chirho);
    assert!(
        warm_session_views_chirho(&keyless_chirho).is_err(),
        "a root whose private key is gone refuses"
    );
    assert_eq!(
        files_chirho(&keyless_chirho),
        keyless_files_chirho,
        "and gets no new key"
    );
}

/// THE DOOR WRITES ONE RECORD PER SESSION: a revocation appends one signed record and the next check sees it; a repeat,
/// by token or by seq, answers that same record and appends nothing; and concurrent revocations, of one session from
/// eight threads and of four other sessions from two threads each, append exactly one record per session, numbered
/// densely, in a log today's verifier accepts. The control: a session nobody revoked still answers.
///
/// MIGRATION PATH: a second record for one session means the door's existing-record check left the append lock.
#[test]
fn the_revocation_door_writes_one_record_per_session_even_concurrently_chirho() {
    let root_chirho = tmp_root_chirho("door");
    let principal_chirho = user_chirho(&root_chirho);
    let logins_chirho: Vec<IdentityLoginResultChirho> = (0..7)
        .map(|_| login_identity_chirho(&root_chirho, &principal_chirho).unwrap())
        .collect();
    let check_chirho = |login_chirho: &IdentityLoginResultChirho| {
        validate_session_token_chirho(&root_chirho, &principal_chirho, &login_chirho.token_chirho)
            .unwrap()
    };
    assert!(check_chirho(&logins_chirho[0]).is_some());
    let first_chirho = revoke_session_token_chirho(
        &root_chirho,
        &principal_chirho,
        &logins_chirho[0].token_chirho,
        "operator-chirho",
        "door arm",
    )
    .unwrap();
    assert_eq!(
        check_chirho(&logins_chirho[0]),
        None,
        "the next check sees the revocation"
    );
    let again_chirho = revoke_session_by_seq_chirho(
        &root_chirho,
        &principal_chirho,
        logins_chirho[0].session_chirho.seq_chirho,
        "operator-chirho",
        "a repeat",
    )
    .unwrap();
    assert_eq!(
        again_chirho, first_chirho,
        "a repeat answers the first record"
    );
    assert_eq!(
        revocation_lines_chirho(&root_chirho),
        1,
        "and appends nothing"
    );

    let mut targets_chirho = vec![1usize; 8];
    for session_chirho in 2..6 {
        targets_chirho.extend([session_chirho, session_chirho]);
    }
    let barrier_chirho = Arc::new(Barrier::new(targets_chirho.len()));
    let handles_chirho: Vec<_> = targets_chirho
        .iter()
        .map(|target_chirho| {
            let root_chirho = root_chirho.clone();
            let principal_chirho = principal_chirho.clone();
            let token_chirho = logins_chirho[*target_chirho].token_chirho.clone();
            let barrier_chirho = Arc::clone(&barrier_chirho);
            let target_chirho = *target_chirho;
            std::thread::spawn(move || {
                barrier_chirho.wait();
                let record_chirho = revoke_session_token_chirho(
                    &root_chirho,
                    &principal_chirho,
                    &token_chirho,
                    "operator-chirho",
                    "concurrent",
                )
                .unwrap();
                (target_chirho, record_chirho)
            })
        })
        .collect();
    let results_chirho: Vec<(usize, IdentitySessionRevocationRecordChirho)> = handles_chirho
        .into_iter()
        .map(|handle_chirho| handle_chirho.join().unwrap())
        .collect();
    for (session_chirho, login_chirho) in logins_chirho.iter().enumerate().take(6).skip(1) {
        let records_chirho: Vec<&IdentitySessionRevocationRecordChirho> = results_chirho
            .iter()
            .filter(|(target_chirho, _)| *target_chirho == session_chirho)
            .map(|(_, record_chirho)| record_chirho)
            .collect();
        assert!(
            records_chirho
                .windows(2)
                .all(|pair_chirho| pair_chirho[0] == pair_chirho[1]),
            "every revoker of session {session_chirho} got the one record"
        );
        assert_eq!(check_chirho(login_chirho), None);
    }
    assert_eq!(
        revocation_lines_chirho(&root_chirho),
        6,
        "one record per revoked session"
    );
    assert_eq!(verify_session_revocations_chirho(&root_chirho).unwrap(), 6);
    assert_eq!(
        check_chirho(&logins_chirho[6]),
        Some(logins_chirho[6].session_chirho.clone()),
        "the control: a session nobody revoked still answers"
    );
}

/// The door refuses to append past a tail it did not verify. A final revocation line without its newline that does not
/// parse is left by the view (a write may be in flight) but counted by the seqlog's recovery, which adds its newline.
/// The two counts then disagree, and the door refuses rather than number a record past bytes it never verified.
///
/// MIGRATION PATH: a second revocation record in the log means the door appended against an unverified tail.
#[test]
fn the_revocation_door_refuses_to_append_past_a_tail_it_did_not_verify_chirho() {
    let root_chirho = tmp_root_chirho("unverified-tail");
    let principal_chirho = user_chirho(&root_chirho);
    let first_chirho = login_identity_chirho(&root_chirho, &principal_chirho).unwrap();
    let second_chirho = login_identity_chirho(&root_chirho, &principal_chirho).unwrap();
    revoke_session_token_chirho(
        &root_chirho,
        &principal_chirho,
        &first_chirho.token_chirho,
        "operator-chirho",
        "tail arm",
    )
    .unwrap();
    let mut file_chirho = std::fs::OpenOptions::new()
        .append(true)
        .open(session_revocations_path_chirho(&root_chirho))
        .unwrap();
    file_chirho.write_all(br#"{"x_chirho":1}"#).unwrap();
    drop(file_chirho);
    let refusal_chirho = revoke_session_token_chirho(
        &root_chirho,
        &principal_chirho,
        &second_chirho.token_chirho,
        "operator-chirho",
        "tail arm",
    )
    .unwrap_err();
    assert!(
        format!("{refusal_chirho:#}").contains("refusing to append"),
        "the counts disagreed: {refusal_chirho:#}"
    );
    assert_eq!(
        revocation_lines_chirho(&root_chirho),
        1,
        "no revocation was appended past the unverified tail"
    );
}
