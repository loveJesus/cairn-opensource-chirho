// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Brick 4a-2b's arms: a key's rate policy above the ceiling is refused at issuance before any credential work, a
//! public key without a policy gets the default, and a principal holds at most five live rate-limited keys, a limit
//! only someone with the password ever learns about (PFE #25915).

use super::*;
use identity_chirho::PrincipalKindChirho;
use std::sync::atomic::AtomicU64;

const SECRET_CHIRHO: &str = "issuance-policy-secret-chirho";
const WRONG_CHIRHO: &str = "issuance-policy-wrong-chirho";
const HOUR_MS_CHIRHO: u64 = 60 * 60 * 1000;

/// A root with an owner, one client, and one user who has a credential.
struct IssuanceFixtureChirho {
    root_chirho: PathBuf,
    client_chirho: OauthClientRecordChirho,
    user_chirho: String,
}

fn issuance_fixture_chirho(label_chirho: &str) -> IssuanceFixtureChirho {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho = COUNTER_CHIRHO.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-issuance-policy-{label_chirho}-{}-{n_chirho}-{}",
        std::process::id(),
        now_ms_chirho()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    let owner_chirho =
        identity_chirho::register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
            .unwrap();
    let client_chirho =
        register_client_chirho(&root_chirho, "alpha", &owner_chirho.principal_chirho).unwrap();
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        SECRET_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    IssuanceFixtureChirho {
        root_chirho,
        client_chirho,
        user_chirho,
    }
}

fn policy_chirho(window_ms_chirho: u64, max_invokes_chirho: u64) -> ScopedTokenRateLimitChirho {
    ScopedTokenRateLimitChirho {
        window_ms_chirho,
        max_invokes_chirho,
        device_id_chirho: None,
    }
}

/// The public road, as the served token endpoint calls it.
fn public_issue_chirho(
    fixture_chirho: &IssuanceFixtureChirho,
    credential_chirho: &str,
    policy_chirho: Option<ScopedTokenRateLimitChirho>,
) -> Result<ScopedTokenIssueChirho> {
    issue_scoped_token_with_public_auth_limit_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.user_chirho,
        credential_chirho,
        &fixture_chirho.client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
        policy_chirho,
        &identity_chirho::SignInVelocityChirho::default(),
    )
}

/// The operator road, as the CLI's `oauth-token` calls it.
fn operator_issue_chirho(
    fixture_chirho: &IssuanceFixtureChirho,
    credential_chirho: &str,
    policy_chirho: Option<ScopedTokenRateLimitChirho>,
) -> Result<ScopedTokenIssueChirho> {
    issue_scoped_token_with_rate_limit_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.user_chirho,
        credential_chirho,
        &fixture_chirho.client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
        policy_chirho,
    )
}

/// The lines of one log in the root: sessions, auth attempts and tokens are what an issuance can write.
fn log_lines_chirho(root_chirho: &Path, file_chirho: &str) -> usize {
    std::fs::read_to_string(root_chirho.join(file_chirho))
        .map(|text_chirho| text_chirho.lines().count())
        .unwrap_or(0)
}

fn written_chirho(root_chirho: &Path) -> [usize; 3] {
    [
        log_lines_chirho(root_chirho, "identity-sessions-chirho.jsonl"),
        log_lines_chirho(root_chirho, "identity-auth-attempts-chirho.jsonl"),
        log_lines_chirho(root_chirho, "scoped-tokens-chirho.jsonl"),
    ]
}

fn is_ceiling_chirho(error_chirho: &anyhow::Error) -> bool {
    error_chirho
        .downcast_ref::<ScopedTokenPolicyAboveCeilingChirho>()
        .is_some()
}

fn is_cap_chirho(error_chirho: &anyhow::Error) -> bool {
    error_chirho
        .downcast_ref::<ScopedTokenCapReachedChirho>()
        .is_some()
}

/// THE CEILING AT ISSUANCE: a policy above one hour or 3,600 invokes is refused, naming the maximum, on the public road
/// and the operator road alike, BEFORE any credential work. So a right and a wrong password get the same refusal, and
/// nothing is written: no session, no auth attempt, no token. A policy exactly at the ceiling is issued.
///
/// MIGRATION PATH: a clamped policy would issue a key here; a check after the sign-in would write a session and an
/// attempt first, and a wrong password would then be told the credential was wrong instead.
#[test]
fn a_policy_above_the_ceiling_is_refused_at_issuance_before_any_credential_work_chirho() {
    let fixture_chirho = issuance_fixture_chirho("ceiling");
    let root_chirho = &fixture_chirho.root_chirho;
    for policy_chirho in [
        policy_chirho(2 * HOUR_MS_CHIRHO, 10),
        policy_chirho(60_000, 3_601),
    ] {
        for credential_chirho in [SECRET_CHIRHO, WRONG_CHIRHO] {
            let before_chirho = written_chirho(root_chirho);
            let refusals_chirho = [
                public_issue_chirho(
                    &fixture_chirho,
                    credential_chirho,
                    Some(policy_chirho.clone()),
                )
                .unwrap_err(),
                operator_issue_chirho(
                    &fixture_chirho,
                    credential_chirho,
                    Some(policy_chirho.clone()),
                )
                .unwrap_err(),
            ];
            for refusal_chirho in &refusals_chirho {
                assert!(
                    is_ceiling_chirho(refusal_chirho),
                    "the ceiling refused: {refusal_chirho:#}"
                );
                let text_chirho = refusal_chirho.to_string();
                assert!(
                    text_chirho.contains("3600000") && text_chirho.contains("3600 invokes"),
                    "the refusal names the maximum: {text_chirho}"
                );
            }
            assert_eq!(
                written_chirho(root_chirho),
                before_chirho,
                "no session, attempt or token was written"
            );
        }
    }
    // The control: an issuance at the ceiling succeeds, and the counter sees its session, attempt and token, so the
    // "nothing written" checks above could fail.
    let before_chirho = written_chirho(root_chirho);
    let at_ceiling_chirho = public_issue_chirho(
        &fixture_chirho,
        SECRET_CHIRHO,
        Some(policy_chirho(HOUR_MS_CHIRHO, 3_600)),
    )
    .unwrap();
    assert_eq!(
        at_ceiling_chirho.record_chirho.rate_limit_chirho,
        Some(policy_chirho(HOUR_MS_CHIRHO, 3_600))
    );
    assert_eq!(
        written_chirho(root_chirho),
        [
            before_chirho[0] + 1,
            before_chirho[1] + 1,
            before_chirho[2] + 1
        ],
        "one session, one attempt and one token"
    );
}

/// THE DEFAULT: a public key requested without a policy is issued with one hour and 600 invokes, and the record says
/// so (the served endpoint returns it). The operator road keeps its choice: no policy there is still no policy.
#[test]
fn a_public_key_requested_without_a_policy_gets_the_default_chirho() {
    let fixture_chirho = issuance_fixture_chirho("default");
    let public_chirho = public_issue_chirho(&fixture_chirho, SECRET_CHIRHO, None).unwrap();
    assert_eq!(
        public_chirho.record_chirho.rate_limit_chirho,
        Some(policy_chirho(
            PUBLIC_TOKEN_DEFAULT_WINDOW_MS_CHIRHO,
            PUBLIC_TOKEN_DEFAULT_MAX_INVOKES_CHIRHO
        ))
    );
    assert_eq!(
        (
            PUBLIC_TOKEN_DEFAULT_WINDOW_MS_CHIRHO,
            PUBLIC_TOKEN_DEFAULT_MAX_INVOKES_CHIRHO
        ),
        (HOUR_MS_CHIRHO, 600),
        "the ruled default (PFE #25915)"
    );
    let operator_chirho = operator_issue_chirho(&fixture_chirho, SECRET_CHIRHO, None).unwrap();
    assert_eq!(operator_chirho.record_chirho.rate_limit_chirho, None);
}

/// THE CAP: a principal's sixth live rate-limited key is refused and nothing is appended; a key without a policy
/// neither counts nor is capped; another principal has its own count; and once the five expire, a new key is issued.
/// The count is read from the token view under the token log's append lock.
///
/// MIGRATION PATH: a sixth key issued means the cap is gone; a refusal after the expiry means expired keys still count,
/// so a principal would be locked out for good.
#[test]
fn a_sixth_live_rate_limited_key_is_refused_and_an_expired_one_frees_a_slot_chirho() {
    let fixture_chirho = issuance_fixture_chirho("cap");
    let root_chirho = &fixture_chirho.root_chirho;
    let issue_at_chirho = |principal_chirho: &str,
                           policy_chirho: Option<ScopedTokenRateLimitChirho>,
                           now_ms_chirho: u64| {
        issue_scoped_token_after_login_at_chirho(
            root_chirho,
            fixture_chirho.client_chirho.clone(),
            identity_chirho::login_identity_chirho(root_chirho, principal_chirho).unwrap(),
            IssuedKeyKindChirho::LegacyChirho(vec!["invoke_chirho".to_string()]),
            policy_chirho,
            || now_ms_chirho,
        )
    };
    let now_chirho = now_ms_chirho();
    for _ in 0..LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO {
        issue_at_chirho(
            &fixture_chirho.user_chirho,
            Some(policy_chirho(60_000, 5)),
            now_chirho,
        )
        .unwrap();
    }
    let tokens_before_chirho = load_scoped_tokens_chirho(root_chirho).unwrap().len();
    let refusal_chirho = issue_at_chirho(
        &fixture_chirho.user_chirho,
        Some(policy_chirho(60_000, 5)),
        now_chirho,
    )
    .unwrap_err();
    assert!(
        is_cap_chirho(&refusal_chirho),
        "the cap refused: {refusal_chirho:#}"
    );
    assert_eq!(
        load_scoped_tokens_chirho(root_chirho).unwrap().len(),
        tokens_before_chirho,
        "nothing appended"
    );
    issue_at_chirho(&fixture_chirho.user_chirho, None, now_chirho)
        .expect("a key without a policy is not capped");
    let other_chirho =
        identity_chirho::register_identity_chirho(root_chirho, PrincipalKindChirho::UserChirho)
            .unwrap()
            .principal_chirho;
    issue_at_chirho(&other_chirho, Some(policy_chirho(60_000, 5)), now_chirho)
        .expect("another principal has its own count");
    // Past the five keys' lifetime (they live as long as their sessions, a day), the slot is free again.
    issue_at_chirho(
        &fixture_chirho.user_chirho,
        Some(policy_chirho(60_000, 5)),
        now_chirho + 25 * HOUR_MS_CHIRHO,
    )
    .expect("an expired key frees its slot");
}

/// THE CAP IS TOLD ONLY TO THE RIGHT PASSWORD: at the cap, a wrong password gets the ordinary credential refusal,
/// exactly as below the cap, and only the right password learns the cap. The cap is checked after the credential is
/// proved, so its sign-in still counts toward the principal's velocity (the session it made is never handed out).
///
/// MIGRATION PATH: a cap refusal for a wrong password means the cap is checked before the credential, which tells
/// anyone without the password that this principal holds five live keys.
#[test]
fn the_cap_is_told_only_to_the_right_password_chirho() {
    let fixture_chirho = issuance_fixture_chirho("cap-oracle");
    let wrong_below_cap_chirho = public_issue_chirho(
        &fixture_chirho,
        WRONG_CHIRHO,
        Some(policy_chirho(60_000, 5)),
    )
    .unwrap_err();
    for _ in 0..LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO {
        public_issue_chirho(
            &fixture_chirho,
            SECRET_CHIRHO,
            Some(policy_chirho(60_000, 5)),
        )
        .unwrap();
    }
    let wrong_at_cap_chirho = public_issue_chirho(
        &fixture_chirho,
        WRONG_CHIRHO,
        Some(policy_chirho(60_000, 5)),
    )
    .unwrap_err();
    assert!(
        !is_cap_chirho(&wrong_at_cap_chirho),
        "a wrong password never learns the cap"
    );
    assert_eq!(
        wrong_at_cap_chirho.to_string(),
        wrong_below_cap_chirho.to_string(),
        "the same refusal at the cap as below it"
    );
    let right_at_cap_chirho = public_issue_chirho(
        &fixture_chirho,
        SECRET_CHIRHO,
        Some(policy_chirho(60_000, 5)),
    )
    .unwrap_err();
    assert!(
        is_cap_chirho(&right_at_cap_chirho),
        "the right password learns the cap"
    );
}
