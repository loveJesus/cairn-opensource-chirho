// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 Part 3's served road under its limits and faults, over a real local server (PFE #26801): the cap and the daily
//! limit told apart, the operator road meeting the same locks for the last daily slot, the faults and the seam after the
//! key, a lost answer, and a repeated POST.

use super::connection_new_http_tests_chirho::{
    assert_guarded_chirho, attempt_rows_chirho, cookie_value_chirho, form_body_chirho,
    form_target_chirho, lines_chirho, location_chirho, post_form_chirho,
    with_connection_road_chirho, CONNECTION_NEW_PATH_CHIRHO,
};
use super::limited_key_fixture_chirho::*;
use super::*;
use identity_chirho::IdentityAuthAttemptOutcomeChirho;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

/// The bearer a one-time page shows.
fn bearer_on_page_chirho(response_chirho: &HttpSmokeResponseChirho) -> String {
    let page_chirho = http_body_text_chirho(response_chirho);
    let start_chirho = page_chirho.find("<code>").expect("a one-time page") + "<code>".len();
    page_chirho[start_chirho..start_chirho + page_chirho[start_chirho..].find("</code>").unwrap()]
        .to_string()
}

/// The principal's own keys, as the engine lists them: (key id, live).
fn own_keys_chirho(root_chirho: &Path, principal_chirho: &str) -> Vec<(String, bool)> {
    oauth_chirho::list_own_keys_chirho(root_chirho, principal_chirho)
        .unwrap()
        .into_iter()
        .map(|row_chirho| (row_chirho.key_id_chirho, row_chirho.live_chirho))
        .collect()
}

fn live_count_chirho(root_chirho: &Path, principal_chirho: &str) -> usize {
    own_keys_chirho(root_chirho, principal_chirho)
        .iter()
        .filter(|(_key_id_chirho, live_chirho)| *live_chirho)
        .count()
}

fn end_all_chirho(root_chirho: &Path, principal_chirho: &str, how_many_chirho: usize) {
    for (key_id_chirho, _live_chirho) in own_keys_chirho(root_chirho, principal_chirho)
        .into_iter()
        .filter(|(_key_id_chirho, live_chirho)| *live_chirho)
        .take(how_many_chirho)
    {
        oauth_chirho::revoke_own_key_chirho(root_chirho, principal_chirho, &key_id_chirho).unwrap();
    }
}

fn set_mode_chirho(path_chirho: &Path, mode_chirho: u32) {
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(mode_chirho)).unwrap();
}

/// THE CAP AND THE DAY OVER HTTP, AND THE OPERATOR ROAD MEETS THE SAME LOCKS: five creations fill the slots, and the sixth
/// is slots-full. Ended, they free the slots and not the day. Four more over HTTP make nine; for the tenth, the operator
/// road holds its locked section after deciding, and the HTTP creation that arrives meets those locks and is refused at
/// the day once it can count. With slots free, the eleventh is refused at the day, not the cap. Only the nine HTTP
/// creations appended attempt rows.
#[test]
fn the_cap_and_the_day_over_http_with_the_operator_road_counted_chirho() {
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("k4p3-limits", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let (principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let principal_chirho = principal_chirho.to_string();
    let secret_chirho = secret_chirho.to_string();
    let client_id_chirho = tenant_chirho.client_id_chirho.clone();
    let cookie_chirho = cookie_value_chirho(&tenant_chirho, 0);
    let body_chirho = form_body_chirho(&client_id_chirho, &[PAGE_READ_CHIRHO], &secret_chirho);
    let target_chirho = form_target_chirho(&client_id_chirho);
    with_connection_road_chirho(&root_chirho, true, |addr_chirho| {
        for _ in 0..oauth_chirho::LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO {
            assert_eq!(
                post_form_chirho(addr_chirho, Some(&cookie_chirho), &body_chirho).status_chirho,
                200
            );
        }
        let full_chirho = post_form_chirho(addr_chirho, Some(&cookie_chirho), &body_chirho);
        assert_eq!(
            (full_chirho.status_chirho, location_chirho(&full_chirho)),
            (
                303,
                format!("{target_chirho}#refusal-connection-slots-full-chirho")
            )
        );
        assert_guarded_chirho(&full_chirho);

        end_all_chirho(&root_chirho, &principal_chirho, usize::MAX);
        for _ in 0..4 {
            assert_eq!(
                post_form_chirho(addr_chirho, Some(&cookie_chirho), &body_chirho).status_chirho,
                200
            );
        }
        assert_eq!(live_count_chirho(&root_chirho, &principal_chirho), 4);

        let (entered_chirho, entered_rx_chirho) = mpsc::channel::<()>();
        let (release_chirho, release_rx_chirho) = mpsc::channel::<()>();
        std::thread::scope(|scope_chirho| {
            let (root_ref_chirho, principal_ref_chirho, secret_ref_chirho, client_ref_chirho) = (
                &root_chirho,
                &principal_chirho,
                &secret_chirho,
                &client_id_chirho,
            );
            let operator_chirho = scope_chirho.spawn(move || {
                oauth_chirho::set_issuance_hold_chirho(move || {
                    entered_chirho.send(()).unwrap();
                    release_rx_chirho.recv().unwrap();
                    Ok(())
                });
                oauth_chirho::issue_limited_key_chirho(
                    root_ref_chirho,
                    principal_ref_chirho,
                    secret_ref_chirho,
                    client_ref_chirho,
                    &[PAGE_READ_CHIRHO.to_string()],
                    None,
                )
            });
            entered_rx_chirho
                .recv_timeout(Duration::from_secs(60))
                .unwrap();
            let served_chirho = scope_chirho
                .spawn(|| post_form_chirho(addr_chirho, Some(&cookie_chirho), &body_chirho));
            std::thread::sleep(Duration::from_millis(300));
            release_chirho.send(()).unwrap();
            operator_chirho
                .join()
                .unwrap()
                .expect("the operator road takes the last daily slot");
            let refused_chirho = served_chirho.join().unwrap();
            assert_eq!(
                (
                    refused_chirho.status_chirho,
                    location_chirho(&refused_chirho)
                ),
                (303, format!("{target_chirho}#refusal-rate-limited-chirho"))
            );
        });

        end_all_chirho(&root_chirho, &principal_chirho, 2);
        assert_eq!(live_count_chirho(&root_chirho, &principal_chirho), 3);
        let day_chirho = post_form_chirho(addr_chirho, Some(&cookie_chirho), &body_chirho);
        assert_eq!(
            (day_chirho.status_chirho, location_chirho(&day_chirho)),
            (303, format!("{target_chirho}#refusal-rate-limited-chirho")),
            "with slots free, the day refuses"
        );
    });
    let rows_chirho = attempt_rows_chirho(&root_chirho);
    assert_eq!(rows_chirho.len(), 9, "{rows_chirho:?}");
    assert!(rows_chirho.iter().all(|(endpoint_chirho, outcome_chirho)| {
        endpoint_chirho == identity_chirho::AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO
            && *outcome_chirho == IdentityAuthAttemptOutcomeChirho::SuccessChirho
    }));
}

/// THE FAULTS AND THE SEAM AFTER THE KEY, BESIDE A SUCCESS CONTROL: with the session log read-only, not-created; with the
/// key log read-only, uncertain; with the attempt log read-only after the key, uncertain, and the connection live; with
/// the one-time page failing after the key, uncertain, and the connection live. Each is a direct 500 page with its token
/// and every guard header, and none carries a key.
#[test]
fn the_faults_and_the_seam_after_the_key_answer_their_pages_chirho() {
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("k4p3-faults", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let (principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let cookie_chirho = cookie_value_chirho(&tenant_chirho, 0);
    let body_chirho = form_body_chirho(
        &tenant_chirho.client_id_chirho,
        &[PAGE_READ_CHIRHO],
        secret_chirho,
    );
    with_connection_road_chirho(&root_chirho, true, |addr_chirho| {
        let control_chirho = post_form_chirho(addr_chirho, Some(&cookie_chirho), &body_chirho);
        assert_eq!(control_chirho.status_chirho, 200, "the success control");
        assert!(!bearer_on_page_chirho(&control_chirho).is_empty());

        let expect_page_chirho = |token_chirho: &str| {
            let answer_chirho = post_form_chirho(addr_chirho, Some(&cookie_chirho), &body_chirho);
            assert_eq!(answer_chirho.status_chirho, 500, "{token_chirho}");
            let page_chirho = http_body_text_chirho(&answer_chirho);
            assert!(
                page_chirho.contains(&format!("id=\"{token_chirho}\"")),
                "{page_chirho}"
            );
            assert!(!page_chirho.contains("<code>"), "no key on a failure page");
            assert_guarded_chirho(&answer_chirho);
        };
        for (log_chirho, token_chirho) in [
            (
                "identity-sessions-chirho.jsonl",
                "connection-not-created-chirho",
            ),
            (
                "connection-tokens-chirho.jsonl",
                "connection-uncertain-chirho",
            ),
            (
                "identity-auth-attempts-chirho.jsonl",
                "connection-uncertain-chirho",
            ),
        ] {
            let path_chirho = root_chirho.join(log_chirho);
            let live_before_chirho = live_count_chirho(&root_chirho, principal_chirho);
            set_mode_chirho(&path_chirho, 0o444);
            assert!(
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path_chirho)
                    .is_err(),
                "needs a user a read-only file stops"
            );
            expect_page_chirho(token_chirho);
            set_mode_chirho(&path_chirho, 0o644);
            let live_after_chirho = live_count_chirho(&root_chirho, principal_chirho);
            if log_chirho == "identity-auth-attempts-chirho.jsonl" {
                assert_eq!(
                    live_after_chirho,
                    live_before_chirho + 1,
                    "the connection exists and is live"
                );
            } else {
                assert_eq!(
                    live_after_chirho, live_before_chirho,
                    "{log_chirho}: no live connection was added"
                );
            }
        }

        let live_before_chirho = live_count_chirho(&root_chirho, principal_chirho);
        super::super::auth_connection_new_chirho::one_time_page_hook_chirho::fail_for_principal_chirho(Some(principal_chirho));
        expect_page_chirho("connection-uncertain-chirho");
        super::super::auth_connection_new_chirho::one_time_page_hook_chirho::fail_for_principal_chirho(None);
        assert_eq!(
            live_count_chirho(&root_chirho, principal_chirho),
            live_before_chirho + 1,
            "a page that failed after the key leaves a live connection"
        );
    });
}

/// A TASK THAT FAILS AFTER THE KEY ANSWERS UNCERTAIN, AND THE CREATION PERSISTS (PFE #26813): beside a live successful
/// creation, the issuance task panics right after the issuer returns, inside the production road's blocking closure.
/// The answer is the direct 500 connection-uncertain page, with every guard header and no key. The owner's list, the key
/// log, the session log and the attempt log each show one more: the creation persisted, and the answer did not say
/// "nothing was created".
#[test]
fn a_task_that_fails_after_the_key_answers_uncertain_and_the_creation_persists_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k4p3-join", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let (principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let cookie_chirho = cookie_value_chirho(&tenant_chirho, 0);
    let body_chirho = form_body_chirho(
        &tenant_chirho.client_id_chirho,
        &[PAGE_READ_CHIRHO],
        secret_chirho,
    );
    let written_chirho = || {
        (
            live_count_chirho(&root_chirho, principal_chirho),
            lines_chirho(&root_chirho, "connection-tokens-chirho.jsonl"),
            lines_chirho(&root_chirho, "identity-sessions-chirho.jsonl"),
            attempt_rows_chirho(&root_chirho).len(),
        )
    };
    with_connection_road_chirho(&root_chirho, true, |addr_chirho| {
        let control_chirho = post_form_chirho(addr_chirho, Some(&cookie_chirho), &body_chirho);
        assert_eq!(
            control_chirho.status_chirho, 200,
            "the live success control"
        );
        assert!(!bearer_on_page_chirho(&control_chirho).is_empty());

        let before_chirho = written_chirho();
        super::super::auth_connection_new_chirho::after_issue_seam_chirho::panic_for_principal_chirho(Some(principal_chirho));
        let answer_chirho = post_form_chirho(addr_chirho, Some(&cookie_chirho), &body_chirho);
        super::super::auth_connection_new_chirho::after_issue_seam_chirho::panic_for_principal_chirho(None);
        assert_eq!(answer_chirho.status_chirho, 500);
        let page_chirho = http_body_text_chirho(&answer_chirho);
        assert!(
            page_chirho.contains("id=\"connection-uncertain-chirho\""),
            "{page_chirho}"
        );
        assert!(!page_chirho.contains("Nothing was created") && !page_chirho.contains("<code>"));
        assert_guarded_chirho(&answer_chirho);
        let after_chirho = written_chirho();
        assert_eq!(
            after_chirho,
            (
                before_chirho.0 + 1,
                before_chirho.1 + 1,
                before_chirho.2 + 1,
                before_chirho.3 + 1
            ),
            "one more live connection, key, session and attempt row: the creation persisted"
        );
        assert_eq!(
            attempt_rows_chirho(&root_chirho).last(),
            Some(&(
                "token-chirho".to_string(),
                IdentityAuthAttemptOutcomeChirho::SuccessChirho
            )),
            "the row the task appended before it failed is the creation's success row"
        );
    });
}

/// A LOST ANSWER LEAVES A LIVE CONNECTION THAT NOTHING SHOWS AGAIN, AND A REPEATED POST CREATES ANOTHER: a POST whose
/// answer its client never reads, and one whose client reads only the status line, each leave a created connection,
/// listed and live, and no route re-shows a key: the list carries ids, apps, actions and instants only. The same form
/// posted twice creates two connections, with two different keys.
#[test]
fn a_lost_answer_and_a_repeated_post_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k4p3-lost", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let (principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let cookie_chirho = cookie_value_chirho(&tenant_chirho, 0);
    let body_chirho = form_body_chirho(
        &tenant_chirho.client_id_chirho,
        &[PAGE_READ_CHIRHO],
        secret_chirho,
    );
    with_connection_road_chirho(&root_chirho, true, |addr_chirho| {
        let request_chirho = format!(
            "POST {CONNECTION_NEW_PATH_CHIRHO} HTTP/1.1\r\nhost: {addr_chirho}\r\nconnection: close\r\ncontent-type: application/x-www-form-urlencoded\r\ncookie: {cookie_chirho}\r\ncontent-length: {}\r\n\r\n{body_chirho}",
            body_chirho.len()
        );
        for (expected_live_chirho, read_status_line_chirho) in [(1, false), (2, true)] {
            let mut stream_chirho = std::net::TcpStream::connect(addr_chirho).unwrap();
            stream_chirho.write_all(request_chirho.as_bytes()).unwrap();
            if read_status_line_chirho {
                let mut status_line_chirho = [0_u8; 12];
                std::io::Read::read_exact(&mut stream_chirho, &mut status_line_chirho).unwrap();
                assert_eq!(&status_line_chirho, b"HTTP/1.1 200");
            }
            let deadline_chirho = std::time::Instant::now() + Duration::from_secs(60);
            while live_count_chirho(&root_chirho, principal_chirho) < expected_live_chirho {
                assert!(
                    std::time::Instant::now() < deadline_chirho,
                    "the unread answer's connection never appeared"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            drop(stream_chirho);
        }
        let listed_chirho =
            oauth_chirho::list_own_keys_chirho(&root_chirho, principal_chirho).unwrap();
        assert_eq!(listed_chirho.len(), 2);
        let row_chirho = serde_json::to_value(&listed_chirho[0]).unwrap();
        let mut fields_chirho: Vec<&str> = row_chirho
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields_chirho.sort();
        assert_eq!(
            fields_chirho,
            [
                "app_chirho",
                "expires_ms_chirho",
                "issued_ms_chirho",
                "key_id_chirho",
                "live_chirho",
                "rate_limit_chirho",
                "scopes_chirho"
            ],
            "the list shows no key"
        );

        let first_chirho = post_form_chirho(addr_chirho, Some(&cookie_chirho), &body_chirho);
        let second_chirho = post_form_chirho(addr_chirho, Some(&cookie_chirho), &body_chirho);
        assert_eq!(
            (first_chirho.status_chirho, second_chirho.status_chirho),
            (200, 200)
        );
        assert_ne!(
            bearer_on_page_chirho(&first_chirho),
            bearer_on_page_chirho(&second_chirho)
        );
        assert_eq!(
            live_count_chirho(&root_chirho, principal_chirho),
            4,
            "the two unread and the two repeated"
        );
    });
}
