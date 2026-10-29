// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 Part 3 on R15's twin (PFE #26801, correction 5): over a root where the served road wrote a connection and its
//! `token-chirho` attempt rows, a success and a failure, R15 answers 404 on the road's route, and the row Part 2's twin
//! measured holds with the served connection beside the others: legacy keys and mints, sign-in, every connection refused,
//! the connection's client unknown, and recovery. Rolled forward, the served connection answers again, and the road
//! serves R15's copy.
//!
//! Run: `CAIRN_R15_TWIN_CHIRHO=<R15's macOS twin> cargo test -p cairn-serve-runtime-chirho --lib r15_over_served -- --ignored --test-threads=1`.

use super::connection_new_http_tests_chirho::{
    attempt_rows_chirho, cookie_value_chirho, form_body_chirho, form_target_chirho,
    keyed_path_for_http_chirho, location_chirho, post_form_chirho, with_connection_road_chirho,
    CONNECTION_NEW_PATH_CHIRHO,
};
use super::connection_real_rollback_tests_chirho::{
    r15_row_chirho, real_state_chirho, six_verifiers_chirho,
};
use super::limited_key_fixture_chirho::*;
use super::limited_key_rollback_tests_chirho::{
    r15_twin_chirho, sign_in_chirho, RootCopyChirho, TwinServerChirho,
};
use super::*;
use identity_chirho::IdentityAuthAttemptOutcomeChirho;

fn bearer_on_page_chirho(response_chirho: &HttpSmokeResponseChirho) -> String {
    let page_chirho = http_body_text_chirho(response_chirho);
    let start_chirho = page_chirho.find("<code>").expect("a one-time page") + "<code>".len();
    page_chirho[start_chirho..start_chirho + page_chirho[start_chirho..].find("</code>").unwrap()]
        .to_string()
}

/// R15 OVER THE SERVED ROAD'S WRITES, THEN ROLL FORWARD.
///
/// MIGRATION PATH: a 404 that is not one means R15 learned the route; a different row means R15's twin, or the
/// successor's records, changed (read it, never wave it through); an R15 sign-in refused means R15 cannot read this
/// road's `token-chirho` rows; a successor verifier refusing means R15 wrote something it cannot read back.
#[test]
#[ignore = "runs R15's twin: set CAIRN_R15_TWIN_CHIRHO and pass --ignored"]
fn r15_over_served_connections_then_roll_forward_chirho() {
    let twin_chirho = r15_twin_chirho();
    let state_chirho = real_state_chirho("k4p3-r15");
    let tenant_chirho = &state_chirho.tenant_chirho;
    let client_id_chirho = tenant_chirho.client_id_chirho.clone();
    let (user1_chirho, secret1_chirho) = tenant_chirho.user_chirho(1);

    // The served road: user 1 creates a connection through the form, and gives one wrong password.
    let served_chirho =
        with_connection_road_chirho(&tenant_chirho.root_chirho, true, |addr_chirho| {
            let cookie_chirho = cookie_value_chirho(tenant_chirho, 1);
            let created_chirho = post_form_chirho(
                addr_chirho,
                Some(&cookie_chirho),
                &form_body_chirho(&client_id_chirho, &[PAGE_READ_CHIRHO], secret1_chirho),
            );
            assert_eq!(created_chirho.status_chirho, 200);
            let refused_chirho = post_form_chirho(
                addr_chirho,
                Some(&cookie_chirho),
                &form_body_chirho(
                    &client_id_chirho,
                    &[PAGE_READ_CHIRHO],
                    "wrong-k4p3-r15-chirho",
                ),
            );
            assert!(
                location_chirho(&refused_chirho).ends_with("#refusal-credential-mismatch-chirho")
            );
            bearer_on_page_chirho(&created_chirho)
        });
    let token_rows_chirho: Vec<IdentityAuthAttemptOutcomeChirho> =
        attempt_rows_chirho(&tenant_chirho.root_chirho)
            .into_iter()
            .filter(|(endpoint_chirho, _outcome_chirho)| {
                endpoint_chirho == identity_chirho::AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO
            })
            .map(|(_endpoint_chirho, outcome_chirho)| outcome_chirho)
            .collect();
    assert_eq!(
        token_rows_chirho,
        [
            IdentityAuthAttemptOutcomeChirho::SuccessChirho,
            IdentityAuthAttemptOutcomeChirho::FailureChirho
        ]
    );

    // R15 over a copy: the route is not there, and its row holds with the served connection beside the others.
    let copy_chirho = RootCopyChirho::of_chirho(&tenant_chirho.root_chirho, "k4p3-r15");
    {
        let r15_chirho = TwinServerChirho::start_chirho(&twin_chirho, &copy_chirho);
        assert_eq!(
            probe_chirho(
                &r15_chirho.addr_chirho,
                "GET",
                &form_target_chirho(&client_id_chirho),
                &[],
                b""
            )
            .0,
            404,
            "R15 has no connection road"
        );
        assert_eq!(
            probe_chirho(
                &r15_chirho.addr_chirho,
                "POST",
                CONNECTION_NEW_PATH_CHIRHO,
                &[("content-type", "application/x-www-form-urlencoded")],
                form_body_chirho(&client_id_chirho, &[PAGE_READ_CHIRHO], secret1_chirho).as_bytes(),
            )
            .0,
            404
        );
    }
    let (row_chirho, _json_minted_chirho) = r15_row_chirho(
        &twin_chirho,
        &copy_chirho,
        &state_chirho,
        &[
            &state_chirho.reset_connection_chirho,
            &state_chirho.kept_connection_chirho,
            &served_chirho,
        ],
    );
    assert_eq!(
        row_chirho,
        "legacy key 200; legacy mint 200, its use 200; sign-in 303, signed-in view 200; connection keys [403, 403, 403]; \
         mint for the connection's client 400; recovery 200, sign-in after it 303 (cookie set)",
        "R15 over the served road's writes: Part 2's row, with the served connection refused beside the others"
    );

    // Roll forward on the copy R15 wrote.
    let _verified_chirho = six_verifiers_chirho(&copy_chirho.tenant_root_chirho);
    identity_chirho::verify_auth_attempts_chirho(&copy_chirho.tenant_root_chirho).unwrap();
    with_connection_road_chirho(&copy_chirho.tenant_root_chirho, true, |addr_chirho| {
        assert_eq!(
            probe_chirho(
                addr_chirho,
                "GET",
                &keyed_path_for_http_chirho(VIEW_ROUTE_CHIRHO),
                &[("authorization", &bearer_chirho(&served_chirho))],
                b"",
            )
            .0,
            200,
            "the served connection answers again"
        );
        let (status_chirho, cookie_chirho) =
            sign_in_chirho(addr_chirho, user1_chirho, secret1_chirho);
        let cookie_chirho =
            cookie_chirho.unwrap_or_else(|| panic!("no session cookie ({status_chirho})"));
        let form_chirho = probe_chirho(
            addr_chirho,
            "GET",
            &form_target_chirho(&client_id_chirho),
            &[("cookie", &cookie_chirho)],
            b"",
        );
        assert_eq!(form_chirho.0, 200, "the road serves R15's copy");
        let created_chirho = post_form_chirho(
            addr_chirho,
            Some(&cookie_chirho),
            &form_body_chirho(&client_id_chirho, &[PAGE_READ_CHIRHO], secret1_chirho),
        );
        assert_eq!(created_chirho.status_chirho, 200, "and creates over it");
    });
}
