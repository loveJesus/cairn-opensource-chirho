// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Brick 4a-2's arms: the token and use views decide exactly as today's full scans, refuse what today's verifier
//! refuses with the same identity, never append a use they cannot decide exactly, and do flat work per bearer request.

use super::*;
use identity_chirho::PrincipalKindChirho;
use std::io::Write;
use std::sync::atomic::AtomicU64;

const HOUR_MS_CHIRHO: u64 = 60 * 60 * 1000;

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho = COUNTER_CHIRHO.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-token-views-{label_chirho}-{}-{n_chirho}-{}",
        std::process::id(),
        now_ms_chirho()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

/// A root with an owner, one client per app, and users with no credential (sessions come from the operator login).
struct FixtureChirho {
    root_chirho: PathBuf,
    clients_chirho: Vec<OauthClientRecordChirho>,
    users_chirho: Vec<String>,
}

fn fixture_chirho(label_chirho: &str, apps_chirho: &[&str], users_chirho: usize) -> FixtureChirho {
    let root_chirho = tmp_root_chirho(label_chirho);
    let owner_chirho =
        identity_chirho::register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
            .unwrap();
    let clients_chirho = apps_chirho
        .iter()
        .map(|app_chirho| {
            register_client_chirho(&root_chirho, app_chirho, &owner_chirho.principal_chirho)
                .unwrap()
        })
        .collect();
    let users_chirho = (0..users_chirho)
        .map(|_| {
            identity_chirho::register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho)
                .unwrap()
                .principal_chirho
        })
        .collect();
    FixtureChirho {
        root_chirho,
        clients_chirho,
        users_chirho,
    }
}

fn policy_chirho(
    window_ms_chirho: u64,
    max_invokes_chirho: u64,
    device_chirho: Option<&str>,
) -> ScopedTokenRateLimitChirho {
    ScopedTokenRateLimitChirho {
        window_ms_chirho,
        max_invokes_chirho,
        device_id_chirho: device_chirho.map(str::to_string),
    }
}

/// A token for `user_chirho` through client `client_chirho`, from a fresh session.
fn issue_chirho(
    fixture_chirho: &FixtureChirho,
    user_chirho: usize,
    client_chirho: usize,
    policy_chirho: Option<ScopedTokenRateLimitChirho>,
) -> ScopedTokenIssueChirho {
    let login_chirho = identity_chirho::login_identity_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.users_chirho[user_chirho],
    )
    .unwrap();
    issue_scoped_token_after_login_chirho(
        &fixture_chirho.root_chirho,
        fixture_chirho.clients_chirho[client_chirho].clone(),
        login_chirho,
        vec!["invoke_chirho".to_string()],
        policy_chirho,
    )
    .unwrap()
}

/// The append door at a chosen time: what `record_scoped_token_use_chirho` runs with the real clock.
fn door_at_chirho(
    root_chirho: &Path,
    token_chirho: &ScopedTokenRecordChirho,
    now_ms_chirho: u64,
) -> Result<ScopedTokenUseRecordChirho> {
    token_use_view_chirho::decide_and_append_use_chirho(
        root_chirho,
        token_chirho,
        token_chirho.rate_limit_chirho.as_ref().unwrap(),
        || now_ms_chirho,
    )
}

fn uses_len_chirho(root_chirho: &Path) -> usize {
    load_scoped_token_uses_chirho(root_chirho).unwrap().len()
}

/// Today's decision, the full scan the door replaced: every use so far, counted by today's predicate.
fn todays_recent_chirho(
    root_chirho: &Path,
    token_chirho: &ScopedTokenRecordChirho,
    now_ms_chirho: u64,
) -> u64 {
    let rate_limit_chirho = token_chirho.rate_limit_chirho.as_ref().unwrap();
    load_scoped_token_uses_chirho(root_chirho)
        .unwrap()
        .iter()
        .filter(|record_chirho| {
            scoped_token_use_matches_rate_key_chirho(
                record_chirho,
                token_chirho,
                rate_limit_chirho,
                now_ms_chirho,
            )
        })
        .count() as u64
}

fn is_rate_limit_chirho(error_chirho: &anyhow::Error) -> bool {
    error_chirho
        .downcast_ref::<RateLimitExceededChirho>()
        .is_some()
}

fn append_raw_line_chirho<T: Serialize>(path_chirho: &Path, record_chirho: &T) {
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

fn signed_use_chirho(
    root_chirho: &Path,
    mut record_chirho: ScopedTokenUseRecordChirho,
) -> ScopedTokenUseRecordChirho {
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &scoped_token_use_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    record_chirho
}

struct RngChirho(u64);

impl RngChirho {
    fn below_chirho(&mut self, bound_chirho: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % bound_chirho
    }
}

/// THE DOOR'S EQUIVALENCE: a random run of uses across principals, apps, shared devices and windows, with the clock
/// moving forward and stepping back within the tolerance, is decided by the door exactly as today's full scan decides
/// it, and the log the door writes is one today's full verifier accepts. The coverage controls prove both outcomes,
/// a step back, and a use matched by principal AND device were all exercised.
///
/// MIGRATION PATH: an admit where today refuses is a bearer over its rate; a refuse where today admits is an outage.
/// A final verify failure means the door wrote a record the verifier refuses for good.
#[test]
fn the_door_decides_as_todays_full_scan_and_writes_a_log_that_verifies_chirho() {
    let fixture_chirho = fixture_chirho("door-equivalence", &["alpha", "beta"], 3);
    let tokens_chirho = [
        issue_chirho(
            &fixture_chirho,
            0,
            0,
            Some(policy_chirho(10_000, 3, Some("d0"))),
        ),
        issue_chirho(&fixture_chirho, 0, 0, Some(policy_chirho(60_000, 5, None))),
        issue_chirho(
            &fixture_chirho,
            1,
            0,
            Some(policy_chirho(HOUR_MS_CHIRHO, 8, Some("d0"))),
        ),
        issue_chirho(
            &fixture_chirho,
            2,
            1,
            Some(policy_chirho(60_000, 4, Some("d1"))),
        ),
        issue_chirho(
            &fixture_chirho,
            2,
            0,
            Some(policy_chirho(30_000, 2, Some("d1"))),
        ),
        issue_chirho(&fixture_chirho, 1, 0, Some(policy_chirho(60_000, 6, None))),
    ];
    let root_chirho = &fixture_chirho.root_chirho;
    let base_chirho = tokens_chirho
        .iter()
        .map(|issue_chirho| issue_chirho.record_chirho.issued_ms_chirho)
        .max()
        .unwrap()
        + 1_000;
    let mut rng_chirho = RngChirho(0x5EED_4A2C);
    let mut now_chirho = base_chirho;
    let (mut admitted_chirho, mut refused_chirho, mut steps_back_chirho, mut double_chirho) =
        (0u64, 0u64, 0u64, 0u64);
    let mut foreign_absent_device_chirho = 0u64;
    for _ in 0..400 {
        if rng_chirho.below_chirho(25) == 0 {
            // A step back within the tolerance (at most 30 minutes), never before the tokens were issued.
            now_chirho = now_chirho
                .saturating_sub(rng_chirho.below_chirho(30 * 60 * 1000))
                .max(base_chirho);
            steps_back_chirho += 1;
        } else {
            now_chirho += rng_chirho.below_chirho(15_000);
        }
        let token_chirho = &tokens_chirho
            [rng_chirho.below_chirho(tokens_chirho.len() as u64) as usize]
            .record_chirho;
        let rate_limit_chirho = token_chirho.rate_limit_chirho.as_ref().unwrap();
        if let Some(device_chirho) = &rate_limit_chirho.device_id_chirho {
            let window_start_chirho = now_chirho.saturating_sub(rate_limit_chirho.window_ms_chirho);
            if load_scoped_token_uses_chirho(root_chirho)
                .unwrap()
                .iter()
                .any(|use_chirho| {
                    use_chirho.app_chirho == token_chirho.app_chirho
                        && use_chirho.principal_chirho == token_chirho.principal_chirho
                        && use_chirho.device_id_chirho.as_ref() == Some(device_chirho)
                        && use_chirho.at_ms_chirho >= window_start_chirho
                })
            {
                double_chirho += 1;
            }
        }
        if rate_limit_chirho.device_id_chirho.is_none() {
            let window_start_chirho = now_chirho.saturating_sub(rate_limit_chirho.window_ms_chirho);
            if load_scoped_token_uses_chirho(root_chirho)
                .unwrap()
                .iter()
                .any(|use_chirho| {
                    use_chirho.app_chirho == token_chirho.app_chirho
                        && use_chirho.principal_chirho != token_chirho.principal_chirho
                        && use_chirho.device_id_chirho.is_none()
                        && use_chirho.at_ms_chirho >= window_start_chirho
                })
            {
                foreign_absent_device_chirho += 1;
            }
        }
        let todays_admits_chirho = todays_recent_chirho(root_chirho, token_chirho, now_chirho)
            < rate_limit_chirho.max_invokes_chirho;
        match door_at_chirho(root_chirho, token_chirho, now_chirho) {
            Ok(_) => {
                assert!(
                    todays_admits_chirho,
                    "the door admitted where today refuses, at {now_chirho}"
                );
                admitted_chirho += 1;
            }
            Err(error_chirho) => {
                assert!(
                    is_rate_limit_chirho(&error_chirho),
                    "not a rate refusal: {error_chirho:#}"
                );
                assert!(
                    !todays_admits_chirho,
                    "the door refused where today admits, at {now_chirho}"
                );
                refused_chirho += 1;
            }
        }
    }
    assert!(
        admitted_chirho > 0 && refused_chirho > 0,
        "both outcomes compared"
    );
    assert!(steps_back_chirho > 0, "a step back was compared");
    assert!(
        double_chirho > 0,
        "a use matched by principal AND device was compared"
    );
    assert!(
        foreign_absent_device_chirho > 0,
        "a device-less key was compared beside another principal's device-less use"
    );
    assert_eq!(
        verify_scoped_token_uses_chirho(root_chirho).unwrap(),
        admitted_chirho as usize,
        "today's full verifier accepts every record the door wrote"
    );
}

/// THE FOLD REFUSES WHAT TODAY'S VERIFIER REFUSES, BY IDENTITY. Each tamper violates ONE property (every other field
/// valid and the record re-signed, except the signature case), so only that property's check can fire. The view
/// refuses it when it folds incrementally, and again on the first load that follows (the error dropped the view).
///
/// MIGRATION PATH: a view that accepts a record today's verifier refuses is a hole in the fold; a different refusal
/// identity means the fixture no longer isolates its property.
#[test]
fn the_fold_refuses_each_tamper_with_todays_identity_chirho() {
    const IDENTITIES_CHIRHO: [&str; 7] = [
        "exceeds rate limit",
        "references missing token",
        "rate policy mismatch",
        "outside token lifetime",
        "signature invalid",
        "seq gap",
        "references an unlimited token",
    ];
    for (case_chirho, identity_chirho) in IDENTITIES_CHIRHO.iter().enumerate() {
        let fixture_chirho = fixture_chirho("fold-tamper", &["alpha"], 1);
        let token_chirho = issue_chirho(
            &fixture_chirho,
            0,
            0,
            Some(policy_chirho(60_000, 2, Some("d0"))),
        )
        .record_chirho;
        let root_chirho = &fixture_chirho.root_chirho;
        let base_chirho = token_chirho.issued_ms_chirho + 1_000;
        door_at_chirho(root_chirho, &token_chirho, base_chirho).unwrap();
        let template_chirho =
            door_at_chirho(root_chirho, &token_chirho, base_chirho + 1_000).unwrap();
        // The positive control: the untampered log verifies both ways.
        assert_eq!(verify_scoped_token_uses_chirho(root_chirho).unwrap(), 2);
        warm_scoped_token_views_chirho(root_chirho).unwrap();
        let mut tamper_chirho = template_chirho.clone();
        tamper_chirho.seq_chirho = 2;
        tamper_chirho.at_ms_chirho = base_chirho + 120_000;
        let tamper_chirho = match case_chirho {
            0 => {
                tamper_chirho.at_ms_chirho = base_chirho + 2_000;
                signed_use_chirho(root_chirho, tamper_chirho)
            }
            1 => {
                tamper_chirho.scoped_token_seq_chirho = 99;
                signed_use_chirho(root_chirho, tamper_chirho)
            }
            2 => {
                tamper_chirho.window_ms_chirho = 59_999;
                signed_use_chirho(root_chirho, tamper_chirho)
            }
            3 => {
                tamper_chirho.at_ms_chirho = token_chirho.expires_ms_chirho + 1;
                signed_use_chirho(root_chirho, tamper_chirho)
            }
            4 => {
                let mut signed_chirho = signed_use_chirho(root_chirho, tamper_chirho);
                signed_chirho.at_ms_chirho += 1;
                signed_chirho
            }
            5 => {
                tamper_chirho.seq_chirho = 7;
                signed_use_chirho(root_chirho, tamper_chirho)
            }
            _ => {
                // A valid token WITHOUT a policy, then a use naming it.
                let mut unlimited_chirho = token_chirho.clone();
                unlimited_chirho.seq_chirho = 1;
                unlimited_chirho.token_hash_chirho = token_hash_chirho("unlimited-token-chirho");
                unlimited_chirho.rate_limit_chirho = None;
                unlimited_chirho.sig_chirho = signer_chirho::sign_message_chirho(
                    root_chirho,
                    &scoped_token_message_chirho(&unlimited_chirho).unwrap(),
                )
                .unwrap();
                append_raw_line_chirho(&scoped_tokens_path_chirho(root_chirho), &unlimited_chirho);
                tamper_chirho.scoped_token_seq_chirho = 1;
                tamper_chirho.token_hash_chirho = unlimited_chirho.token_hash_chirho.clone();
                signed_use_chirho(root_chirho, tamper_chirho)
            }
        };
        append_raw_line_chirho(&scoped_token_uses_path_chirho(root_chirho), &tamper_chirho);
        let refusals_chirho = [
            format!(
                "{:#}",
                verify_scoped_token_uses_chirho(root_chirho).unwrap_err()
            ),
            format!(
                "{:#}",
                warm_scoped_token_views_chirho(root_chirho).unwrap_err()
            ),
            format!(
                "{:#}",
                warm_scoped_token_views_chirho(root_chirho).unwrap_err()
            ),
        ];
        for (road_chirho, refusal_chirho) in ["full verifier", "incremental fold", "first load"]
            .iter()
            .zip(&refusals_chirho)
        {
            assert!(
                refusal_chirho.contains(identity_chirho),
                "case {case_chirho}, {road_chirho}: expected '{identity_chirho}', got: {refusal_chirho}"
            );
            for other_chirho in IDENTITIES_CHIRHO
                .iter()
                .filter(|other_chirho| *other_chirho != identity_chirho)
            {
                assert!(
                    !refusal_chirho.contains(other_chirho),
                    "case {case_chirho}, {road_chirho}: '{other_chirho}' fired too: {refusal_chirho}"
                );
            }
        }
    }
}

/// THE DOOR NEVER APPENDS A USE IT CANNOT DECIDE EXACTLY. After the clock steps back further than the tolerance,
/// a key whose window reaches below the retained history is refused as transient (not admitted from a count missing
/// pruned uses, which would write a record today's verifier refuses for good), and nothing is appended. Once the
/// rebuilt index swaps in, the same request is decided exactly: here refused at its limit, as today decides it.
///
/// MIGRATION PATH: an Ok at the step back is the defect: the door counted only the retained use, admitted a fifth
/// use over a limit of three, and the final verify would then fail.
#[test]
fn a_step_back_beyond_the_tolerance_refuses_until_the_rebuild_then_decides_exactly_chirho() {
    let fixture_chirho = fixture_chirho("step-back", &["alpha"], 1);
    let token_chirho = issue_chirho(
        &fixture_chirho,
        0,
        0,
        Some(policy_chirho(HOUR_MS_CHIRHO, 3, None)),
    )
    .record_chirho;
    let root_chirho = &fixture_chirho.root_chirho;
    let t_chirho = token_chirho.issued_ms_chirho + HOUR_MS_CHIRHO;
    for at_ms_chirho in [t_chirho, t_chirho + 1_000, t_chirho + 2_000] {
        door_at_chirho(root_chirho, &token_chirho, at_ms_chirho).unwrap();
    }
    // Two and a half hours later: the three uses fall below the horizon and are pruned.
    door_at_chirho(root_chirho, &token_chirho, t_chirho + 9_000_000).unwrap();
    let back_chirho = t_chirho + 1_800_000;
    assert_eq!(
        todays_recent_chirho(root_chirho, &token_chirho, back_chirho),
        4,
        "today counts all four"
    );
    let refusal_chirho = door_at_chirho(root_chirho, &token_chirho, back_chirho).unwrap_err();
    assert!(
        refusal_chirho
            .downcast_ref::<UseWindowCatchingUpChirho>()
            .is_some(),
        "expected the transient refusal, got: {refusal_chirho:#}"
    );
    assert_eq!(uses_len_chirho(root_chirho), 4, "nothing appended");
    let decided_chirho =
        door_after_rebuild_chirho(root_chirho, &token_chirho, back_chirho).unwrap_err();
    assert!(
        is_rate_limit_chirho(&decided_chirho),
        "decided exactly: {decided_chirho:#}"
    );
    assert_eq!(uses_len_chirho(root_chirho), 4);
    assert_eq!(verify_scoped_token_uses_chirho(root_chirho).unwrap(), 4);
}

/// The door at `now_ms_chirho` once the background rebuild has swapped in. Until then it refuses as transient and
/// appends nothing; the wait is on that condition, bounded generously (the rebuild of a few records takes milliseconds).
fn door_after_rebuild_chirho(
    root_chirho: &Path,
    token_chirho: &ScopedTokenRecordChirho,
    now_ms_chirho: u64,
) -> Result<ScopedTokenUseRecordChirho> {
    let deadline_chirho = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        match door_at_chirho(root_chirho, token_chirho, now_ms_chirho) {
            Err(error_chirho)
                if error_chirho
                    .downcast_ref::<UseWindowCatchingUpChirho>()
                    .is_some() =>
            {
                assert!(
                    std::time::Instant::now() < deadline_chirho,
                    "the rebuilt index never swapped in"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            outcome_chirho => return outcome_chirho,
        }
    }
}

/// A root for the growth arm: `users_chirho` users, each with `extra_sessions_chirho` sessions no token uses and
/// `tokens_chirho` rate-limited tokens, then `uses_chirho` uses spread across the tokens. Returns the first token.
fn grown_root_chirho(
    label_chirho: &str,
    users_chirho: usize,
    extra_sessions_chirho: usize,
    tokens_chirho: usize,
    uses_chirho: usize,
) -> (PathBuf, ScopedTokenIssueChirho) {
    let fixture_chirho = fixture_chirho(label_chirho, &["alpha"], users_chirho);
    let mut issued_chirho = Vec::new();
    for user_chirho in 0..users_chirho {
        for _ in 0..extra_sessions_chirho {
            identity_chirho::login_identity_chirho(
                &fixture_chirho.root_chirho,
                &fixture_chirho.users_chirho[user_chirho],
            )
            .unwrap();
        }
        for _ in 0..tokens_chirho {
            issued_chirho.push(issue_chirho(
                &fixture_chirho,
                user_chirho,
                0,
                Some(policy_chirho(HOUR_MS_CHIRHO, 3_600, None)),
            ));
        }
    }
    for n_chirho in 0..uses_chirho {
        record_scoped_token_use_chirho(
            &fixture_chirho.root_chirho,
            &issued_chirho[n_chirho % issued_chirho.len()].record_chirho,
        )
        .unwrap()
        .unwrap();
    }
    (fixture_chirho.root_chirho, issued_chirho.swap_remove(0))
}

/// (session-log parses, token records checked, use records folded) on this thread.
fn work_chirho() -> (u64, u64, u64) {
    let (token_checks_chirho, use_folds_chirho) = token_view_metrics_chirho::counts_chirho();
    (
        identity_chirho::session_read_metrics_chirho::count_chirho(),
        token_checks_chirho,
        use_folds_chirho,
    )
}

fn delta_chirho(after_chirho: (u64, u64, u64), before_chirho: (u64, u64, u64)) -> (u64, u64, u64) {
    (
        after_chirho.0 - before_chirho.0,
        after_chirho.1 - before_chirho.1,
        after_chirho.2 - before_chirho.2,
    )
}

/// One bearer request's oauth work: validate the token for its app, then record the use.
fn bearer_request_chirho(root_chirho: &Path, issue_chirho: &ScopedTokenIssueChirho) {
    let record_chirho =
        validate_scoped_token_for_app_chirho(root_chirho, "alpha", &issue_chirho.token_chirho)
            .unwrap()
            .expect("the token validates");
    record_scoped_token_use_chirho(root_chirho, &record_chirho)
        .unwrap()
        .unwrap();
}

/// GROWTH: a bearer request parses the session log zero times, checks no token record and folds one use (the
/// previous request's), whether the root holds 1 user with 2 sessions and 3 uses or 10 users with 90 sessions, 30
/// tokens and 150 uses. The controls show the counters fire: building the root first-loads both views on this
/// thread, which checks every token and parses the session log.
///
/// MIGRATION PATH: a request that parses sessions or checks tokens again is census row 2's multiplier back, the
/// slope PFE's part 7 and part 10 measure.
#[test]
fn a_bearer_requests_counted_work_is_flat_in_sessions_tokens_and_uses_chirho() {
    let mut per_request_chirho = Vec::new();
    for (label_chirho, users_chirho, extra_chirho, tokens_chirho, uses_chirho) in [
        ("growth-small", 1, 1, 1, 3),
        ("growth-large", 10, 6, 3, 150),
    ] {
        let before_build_chirho = work_chirho();
        let (root_chirho, issue_chirho) = grown_root_chirho(
            label_chirho,
            users_chirho,
            extra_chirho,
            tokens_chirho,
            uses_chirho,
        );
        let build_chirho = delta_chirho(work_chirho(), before_build_chirho);
        assert!(
            build_chirho.0 > 0,
            "{label_chirho}: the first load parses the session log"
        );
        assert!(
            build_chirho.1 >= (users_chirho * tokens_chirho) as u64,
            "{label_chirho}: the first load checks every token"
        );
        bearer_request_chirho(&root_chirho, &issue_chirho);
        let before_chirho = work_chirho();
        bearer_request_chirho(&root_chirho, &issue_chirho);
        per_request_chirho.push(delta_chirho(work_chirho(), before_chirho));
    }
    assert_eq!(
        per_request_chirho[0],
        (0, 0, 1),
        "small root: no sessions, no tokens, one use"
    );
    assert_eq!(
        per_request_chirho[1], per_request_chirho[0],
        "the large root's request does the same work"
    );
}

/// A legacy token whose policy is above today's ceiling still VALIDATES (today's verifier accepts it in history),
/// but its use is refused with a reason to reissue it, and nothing is appended. A policy exactly at the ceiling is
/// served (agy #25928, ruling (c)(i)).
#[test]
fn a_token_above_the_ceiling_is_refused_at_use_with_a_reason_to_reissue_chirho() {
    let fixture_chirho = fixture_chirho("ceiling", &["alpha"], 1);
    let root_chirho = &fixture_chirho.root_chirho;
    let normal_chirho =
        issue_chirho(&fixture_chirho, 0, 0, Some(policy_chirho(60_000, 5, None))).record_chirho;
    let craft_chirho = |seq_chirho: u64, policy_chirho: ScopedTokenRateLimitChirho| {
        let token_chirho = format!("legacy-token-{seq_chirho}-chirho");
        let mut record_chirho = normal_chirho.clone();
        record_chirho.seq_chirho = seq_chirho;
        record_chirho.token_hash_chirho = token_hash_chirho(&token_chirho);
        record_chirho.rate_limit_chirho = Some(policy_chirho);
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &scoped_token_message_chirho(&record_chirho).unwrap(),
        )
        .unwrap();
        append_raw_line_chirho(&scoped_tokens_path_chirho(root_chirho), &record_chirho);
        token_chirho
    };
    let cases_chirho = [
        (
            craft_chirho(1, policy_chirho(2 * HOUR_MS_CHIRHO, 10, None)),
            false,
        ),
        (craft_chirho(2, policy_chirho(60_000, 3_601, None)), false),
        (
            craft_chirho(3, policy_chirho(HOUR_MS_CHIRHO, 3_600, None)),
            true,
        ),
    ];
    assert_eq!(
        verify_scoped_tokens_chirho(root_chirho).unwrap(),
        4,
        "history accepts them all"
    );
    for (token_chirho, served_chirho) in cases_chirho {
        let record_chirho =
            validate_scoped_token_for_app_chirho(root_chirho, "alpha", &token_chirho)
                .unwrap()
                .expect("an above-ceiling token still validates");
        let before_chirho = uses_len_chirho(root_chirho);
        let outcome_chirho = record_scoped_token_use_chirho(root_chirho, &record_chirho);
        if served_chirho {
            assert!(
                outcome_chirho.unwrap().is_some(),
                "at the ceiling is served"
            );
            assert_eq!(uses_len_chirho(root_chirho), before_chirho + 1);
        } else {
            let refusal_chirho = outcome_chirho.unwrap_err();
            assert!(
                refusal_chirho
                    .downcast_ref::<ScopedTokenPolicyAboveCeilingChirho>()
                    .is_some(),
                "expected the ceiling refusal, got: {refusal_chirho:#}"
            );
            assert!(
                format!("{refusal_chirho}").contains("issue a key within them"),
                "the refusal says how to recover: {refusal_chirho}"
            );
            assert_eq!(
                uses_len_chirho(root_chirho),
                before_chirho,
                "nothing appended"
            );
        }
    }
}

/// CONCURRENCY: eight threads recording uses of one key while two validate in a loop admit EXACTLY the limit, refuse
/// the rest as rate limits, and leave a log today's verifier accepts. The decision and the record are one act under
/// the append-log lock, with the use view and the token view taken in their documented order.
#[test]
fn concurrent_uses_of_one_key_admit_exactly_the_limit_chirho() {
    let fixture_chirho = fixture_chirho("concurrent", &["alpha"], 1);
    let issue_chirho = issue_chirho(
        &fixture_chirho,
        0,
        0,
        Some(policy_chirho(HOUR_MS_CHIRHO, 25, None)),
    );
    let root_chirho = fixture_chirho.root_chirho.clone();
    let outcomes_chirho = std::thread::scope(|scope_chirho| {
        let mut recorders_chirho = Vec::new();
        for _ in 0..8 {
            let root_chirho = &root_chirho;
            let record_chirho = &issue_chirho.record_chirho;
            recorders_chirho.push(scope_chirho.spawn(move || {
                (0..10)
                    .map(|_| record_scoped_token_use_chirho(root_chirho, record_chirho))
                    .collect::<Vec<_>>()
            }));
        }
        for _ in 0..2 {
            let root_chirho = &root_chirho;
            let token_chirho = &issue_chirho.token_chirho;
            scope_chirho.spawn(move || {
                for _ in 0..20 {
                    assert!(validate_scoped_token_for_app_chirho(
                        root_chirho,
                        "alpha",
                        token_chirho
                    )
                    .unwrap()
                    .is_some());
                }
            });
        }
        recorders_chirho
            .into_iter()
            .flat_map(|recorder_chirho| recorder_chirho.join().unwrap())
            .collect::<Vec<_>>()
    });
    let admitted_chirho = outcomes_chirho
        .iter()
        .filter(|outcome_chirho| outcome_chirho.is_ok())
        .count();
    let rate_limited_chirho = outcomes_chirho
        .iter()
        .filter(|outcome_chirho| outcome_chirho.as_ref().is_err_and(is_rate_limit_chirho))
        .count();
    assert_eq!(admitted_chirho, 25);
    assert_eq!(
        rate_limited_chirho, 55,
        "every other outcome is a rate refusal"
    );
    assert_eq!(verify_scoped_token_uses_chirho(&root_chirho).unwrap(), 25);
}

/// A FULL PASS VERIFIES EVERY SESSION, as today's verifier does: a tampered session no token references makes the
/// token view's first load refuse, so validation refuses. The twin root without the tamper validates (the control).
/// (An incremental call does not re-read sessions; the hourly integrity pass is what finds such a tamper then, by
/// ruling (a).)
#[test]
fn a_full_pass_refuses_a_tampered_session_no_token_references_chirho() {
    let mut outcomes_chirho = Vec::new();
    for tamper_chirho in [false, true] {
        let fixture_chirho = fixture_chirho("unreferenced-session", &["alpha"], 1);
        let issue_chirho =
            issue_chirho(&fixture_chirho, 0, 0, Some(policy_chirho(60_000, 5, None)));
        let root_chirho = &fixture_chirho.root_chirho;
        identity_chirho::login_identity_chirho(root_chirho, &fixture_chirho.users_chirho[0])
            .unwrap();
        if tamper_chirho {
            let path_chirho = root_chirho.join("identity-sessions-chirho.jsonl");
            let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
            let mut lines_chirho: Vec<String> = text_chirho.lines().map(str::to_string).collect();
            let last_chirho = lines_chirho.last_mut().unwrap();
            let mut session_chirho: serde_json::Value = serde_json::from_str(last_chirho).unwrap();
            let expires_chirho = session_chirho["expires_ms_chirho"].as_u64().unwrap();
            session_chirho["expires_ms_chirho"] = serde_json::json!(expires_chirho + 1);
            *last_chirho = serde_json::to_string(&session_chirho).unwrap();
            std::fs::write(&path_chirho, lines_chirho.join("\n") + "\n").unwrap();
        }
        outcomes_chirho.push(validate_scoped_token_for_app_chirho(
            root_chirho,
            "alpha",
            &issue_chirho.token_chirho,
        ));
    }
    assert!(
        outcomes_chirho[0].as_ref().unwrap().is_some(),
        "the control validates"
    );
    let refusal_chirho = outcomes_chirho[1].as_ref().unwrap_err();
    assert!(
        format!("{refusal_chirho:#}").contains("identity session"),
        "the session check refused: {refusal_chirho:#}"
    );
}

/// THE TOKEN FOLD REFUSES WHAT TODAY'S TOKEN VERIFIER REFUSES, BY IDENTITY: each crafted token violates one property
/// (re-signed, except the signature case). The view refuses it when it folds incrementally and again on the first load
/// that follows, and every bearer request on the root refuses meanwhile, as today's full verifier would.
///
/// MIGRATION PATH: an accepted crafted token is a bearer the full verifier refuses; a different identity means the
/// fixture no longer isolates its property.
#[test]
fn the_token_fold_refuses_each_tamper_with_todays_identity_chirho() {
    const IDENTITIES_CHIRHO: [&str; 5] = [
        "signature invalid",
        "unknown client",
        "session time mismatch",
        "seq gap",
        "app does not match client",
    ];
    for (case_chirho, identity_chirho) in IDENTITIES_CHIRHO.iter().enumerate() {
        let fixture_chirho = fixture_chirho("token-fold-tamper", &["alpha", "beta"], 1);
        let issue_chirho =
            issue_chirho(&fixture_chirho, 0, 0, Some(policy_chirho(60_000, 5, None)));
        let root_chirho = &fixture_chirho.root_chirho;
        let validate_chirho = || {
            validate_scoped_token_for_app_chirho(root_chirho, "alpha", &issue_chirho.token_chirho)
        };
        // The positive control: the untampered log verifies, and the view is built.
        assert_eq!(verify_scoped_tokens_chirho(root_chirho).unwrap(), 1);
        assert!(validate_chirho().unwrap().is_some());
        let mut crafted_chirho = issue_chirho.record_chirho.clone();
        crafted_chirho.seq_chirho = 1;
        crafted_chirho.token_hash_chirho = token_hash_chirho("crafted-token-chirho");
        match case_chirho {
            1 => crafted_chirho.client_id_chirho = "client-nope-chirho".to_string(),
            2 => crafted_chirho.expires_ms_chirho += 1,
            3 => crafted_chirho.seq_chirho = 5,
            4 => crafted_chirho.app_chirho = "beta".to_string(),
            _ => {}
        }
        crafted_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &scoped_token_message_chirho(&crafted_chirho).unwrap(),
        )
        .unwrap();
        if case_chirho == 0 {
            crafted_chirho
                .scopes_chirho
                .push("admin_chirho".to_string());
        }
        append_raw_line_chirho(&scoped_tokens_path_chirho(root_chirho), &crafted_chirho);
        let refusals_chirho = [
            format!(
                "{:#}",
                verify_scoped_tokens_chirho(root_chirho).unwrap_err()
            ),
            format!("{:#}", validate_chirho().unwrap_err()),
            format!("{:#}", validate_chirho().unwrap_err()),
        ];
        for (road_chirho, refusal_chirho) in ["full verifier", "incremental fold", "first load"]
            .iter()
            .zip(&refusals_chirho)
        {
            assert!(
                refusal_chirho.contains(identity_chirho),
                "case {case_chirho}, {road_chirho}: expected '{identity_chirho}', got: {refusal_chirho}"
            );
            for other_chirho in IDENTITIES_CHIRHO
                .iter()
                .filter(|other_chirho| *other_chirho != identity_chirho)
            {
                assert!(
                    !refusal_chirho.contains(other_chirho),
                    "case {case_chirho}, {road_chirho}: '{other_chirho}' fired too: {refusal_chirho}"
                );
            }
        }
    }
}

/// A NEW TOKEN'S OWN SESSION IS VERIFIED WHEN THE TOKEN IS FOLDED. The session is tampered in a field its signature
/// covers but the token check does not read, after the view was built, and a token is then issued from it: the
/// incremental fold refuses, as today's full verifier does. Without the fold's session check, the view would serve a
/// token whose session no longer verifies until the next hourly pass.
///
/// Since brick 4b-2 the issuance cap reads the session index, so a CAPPED issuance from the tampered root refuses at
/// issue time already, with the same identity. The fold's own check is therefore exercised on a key issued without a
/// policy, which the cap does not count, and the capped refusal is asserted beside it.
///
/// MIGRATION PATH: the uncapped key answering means the fold stopped checking its session; the capped issuance
/// succeeding means the cap stopped reading live sessions.
#[test]
fn a_new_tokens_tampered_session_is_refused_when_the_token_is_folded_chirho() {
    let fixture_chirho = fixture_chirho("token-session-tamper", &["alpha"], 1);
    let first_chirho = issue_chirho(&fixture_chirho, 0, 0, Some(policy_chirho(60_000, 5, None)));
    let root_chirho = &fixture_chirho.root_chirho;
    assert!(
        validate_scoped_token_for_app_chirho(root_chirho, "alpha", &first_chirho.token_chirho)
            .unwrap()
            .is_some(),
        "the control: the view is built and serves"
    );
    let login_chirho =
        identity_chirho::login_identity_chirho(root_chirho, &fixture_chirho.users_chirho[0])
            .unwrap();
    let path_chirho = root_chirho.join("identity-sessions-chirho.jsonl");
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    let mut lines_chirho: Vec<String> = text_chirho.lines().map(str::to_string).collect();
    let last_chirho = lines_chirho.last_mut().unwrap();
    let mut session_chirho: serde_json::Value = serde_json::from_str(last_chirho).unwrap();
    // The session's own token hash: covered by its signature, never read by the token check.
    assert!(
        session_chirho["token_hash_chirho"].is_string(),
        "the tampered field is present"
    );
    session_chirho["token_hash_chirho"] = serde_json::json!("00".repeat(32));
    *last_chirho = serde_json::to_string(&session_chirho).unwrap();
    std::fs::write(&path_chirho, lines_chirho.join("\n") + "\n").unwrap();
    let second_chirho = issue_scoped_token_after_login_chirho(
        root_chirho,
        fixture_chirho.clients_chirho[0].clone(),
        login_chirho,
        vec!["invoke_chirho".to_string()],
        None,
    )
    .unwrap();
    let refusal_chirho =
        validate_scoped_token_for_app_chirho(root_chirho, "alpha", &second_chirho.token_chirho)
            .unwrap_err();
    assert!(
        format!("{refusal_chirho:#}").contains("identity session"),
        "the fold's session check refused: {refusal_chirho:#}"
    );
    assert!(
        verify_scoped_tokens_chirho(root_chirho).is_err(),
        "today's verifier refuses too"
    );
    let capped_login_chirho =
        identity_chirho::login_identity_chirho(root_chirho, &fixture_chirho.users_chirho[0])
            .unwrap();
    let capped_refusal_chirho = issue_scoped_token_after_login_chirho(
        root_chirho,
        fixture_chirho.clients_chirho[0].clone(),
        capped_login_chirho,
        vec!["invoke_chirho".to_string()],
        Some(policy_chirho(60_000, 5, None)),
    )
    .unwrap_err();
    assert!(
        format!("{capped_refusal_chirho:#}").contains("identity session"),
        "a capped issuance refuses at issue time, since the cap reads live sessions: {capped_refusal_chirho:#}"
    );
}

/// THE DOOR NEVER APPENDS PAST A TAIL IT DID NOT VERIFY. A final line that parses as JSON but is no use record, with
/// no newline, is left by the view (a write may be in flight) but counted by the seqlog's recovery, which adds its
/// newline. The two counts then disagree, and the door refuses rather than append a record numbered past bytes it
/// never verified.
///
/// MIGRATION PATH: a second use record in the log means the door appended against an unverified tail.
#[test]
fn the_door_refuses_to_append_past_a_tail_it_did_not_verify_chirho() {
    let fixture_chirho = fixture_chirho("unverified-tail", &["alpha"], 1);
    let token_chirho = issue_chirho(
        &fixture_chirho,
        0,
        0,
        Some(policy_chirho(HOUR_MS_CHIRHO, 50, None)),
    )
    .record_chirho;
    let root_chirho = &fixture_chirho.root_chirho;
    let at_chirho = token_chirho.issued_ms_chirho + 1_000;
    door_at_chirho(root_chirho, &token_chirho, at_chirho).unwrap();
    let path_chirho = scoped_token_uses_path_chirho(root_chirho);
    let mut file_chirho = std::fs::OpenOptions::new()
        .append(true)
        .open(&path_chirho)
        .unwrap();
    file_chirho.write_all(br#"{"x_chirho":1}"#).unwrap();
    drop(file_chirho);
    let refusal_chirho = door_at_chirho(root_chirho, &token_chirho, at_chirho + 1_000).unwrap_err();
    assert!(
        format!("{refusal_chirho:#}").contains("refusing to append"),
        "the counts disagreed: {refusal_chirho:#}"
    );
    let records_chirho = std::fs::read_to_string(&path_chirho)
        .unwrap()
        .lines()
        .filter(|line_chirho| {
            serde_json::from_str::<ScopedTokenUseRecordChirho>(line_chirho).is_ok()
        })
        .count();
    assert_eq!(
        records_chirho, 1,
        "no use was appended past the unverified tail"
    );
}

/// The door refuses a use outside its token's lifetime and appends nothing, so it never writes a record today's
/// verifier refuses as "outside token lifetime". The control: a use inside the lifetime is recorded.
#[test]
fn the_door_refuses_a_use_outside_its_tokens_lifetime_chirho() {
    let fixture_chirho = fixture_chirho("lifetime", &["alpha"], 1);
    let token_chirho =
        issue_chirho(&fixture_chirho, 0, 0, Some(policy_chirho(60_000, 5, None))).record_chirho;
    let root_chirho = &fixture_chirho.root_chirho;
    for at_ms_chirho in [
        token_chirho.issued_ms_chirho - 1,
        token_chirho.expires_ms_chirho + 1,
    ] {
        let refusal_chirho = door_at_chirho(root_chirho, &token_chirho, at_ms_chirho).unwrap_err();
        assert!(
            format!("{refusal_chirho:#}").contains("outside its lifetime"),
            "refused for its lifetime: {refusal_chirho:#}"
        );
    }
    assert!(
        !scoped_token_uses_path_chirho(root_chirho).exists(),
        "nothing was appended"
    );
    door_at_chirho(
        root_chirho,
        &token_chirho,
        token_chirho.issued_ms_chirho + 1,
    )
    .unwrap();
    assert_eq!(verify_scoped_token_uses_chirho(root_chirho).unwrap(), 1);
}

/// THE SIGN-IN ROAD PARSES NO SESSION OR CLIENT LOG, at 1, 10 and 100 sessions and clients: the growth gate's Covered
/// rows for those two sinks on that road. The gate's call graph reaches them from sign-in only through the shared
/// prefix-view engine's generic fold (the token view's), which this road never folds. So this arm pins that a sign-in
/// does none of that work, and a later change that makes it read either log turns red. The control: one direct load
/// of each log moves its counter.
#[test]
fn a_public_sign_in_parses_no_session_or_client_log_at_any_history_chirho() {
    const SECRET_CHIRHO: &str = "sign-in-growth-secret-chirho";
    let mut per_history_chirho = Vec::new();
    for history_chirho in [1usize, 10, 100] {
        let root_chirho = tmp_root_chirho("sign-in-growth");
        let owner_chirho = identity_chirho::register_identity_chirho(
            &root_chirho,
            PrincipalKindChirho::OwnerChirho,
        )
        .unwrap();
        let user_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            PrincipalKindChirho::UserChirho,
            SECRET_CHIRHO,
        )
        .unwrap();
        for n_chirho in 0..history_chirho {
            identity_chirho::login_identity_chirho(&root_chirho, &user_chirho.principal_chirho)
                .unwrap();
            register_client_chirho(
                &root_chirho,
                &format!("app-{n_chirho}"),
                &owner_chirho.principal_chirho,
            )
            .unwrap();
        }
        let velocity_chirho = identity_chirho::SignInVelocityChirho::default();
        let sign_in_chirho = || {
            identity_chirho::login_identity_with_public_auth_limit_for_endpoint_chirho(
                &root_chirho,
                &user_chirho.principal_chirho,
                SECRET_CHIRHO,
                identity_chirho::AUTH_ENDPOINT_LOGIN_CHIRHO,
                &velocity_chirho,
            )
            .unwrap()
        };
        // The first sign-in builds the attempt view; the second is the warm one measured.
        sign_in_chirho();
        let sessions_before_chirho = identity_chirho::session_read_metrics_chirho::count_chirho();
        let clients_before_chirho = token_view_metrics_chirho::client_reads_chirho();
        sign_in_chirho();
        per_history_chirho.push((
            identity_chirho::session_read_metrics_chirho::count_chirho() - sessions_before_chirho,
            token_view_metrics_chirho::client_reads_chirho() - clients_before_chirho,
        ));
        // The control: the counters see a direct load on this thread.
        let sessions_chirho = identity_chirho::session_read_metrics_chirho::count_chirho();
        let clients_chirho = token_view_metrics_chirho::client_reads_chirho();
        identity_chirho::load_sessions_chirho(&root_chirho).unwrap();
        load_clients_chirho(&root_chirho).unwrap();
        assert_eq!(
            identity_chirho::session_read_metrics_chirho::count_chirho(),
            sessions_chirho + 1
        );
        assert_eq!(
            token_view_metrics_chirho::client_reads_chirho(),
            clients_chirho + 1
        );
    }
    assert_eq!(
        per_history_chirho,
        vec![(0, 0); 3],
        "(session parses, client parses) per warm sign-in at 1, 10 and 100"
    );
}
