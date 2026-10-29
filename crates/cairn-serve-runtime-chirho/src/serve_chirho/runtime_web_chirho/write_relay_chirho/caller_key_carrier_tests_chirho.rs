// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The carrier issues one fresh key per empty placeholder, reads exactly one valid key from a form or
//! the header and strips it from the business body, refuses multipart and every malformed shape before
//! any run, and answers a refused form POST with a 303 to a validated same-app page.

use super::*;
use axum::http::HeaderMap;

fn form_headers_chirho() -> HeaderMap {
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
    );
    headers_chirho
}

fn with_header_key_chirho(mut headers_chirho: HeaderMap, key_chirho: &'static str) -> HeaderMap {
    headers_chirho.append(
        CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static(key_chirho),
    );
    headers_chirho
}

fn issued_keys_chirho(page_chirho: &str) -> Vec<String> {
    let prefix_chirho = format!("name=\"{FORM_CALLER_KEY_FIELD_CHIRHO}\" value=\"");
    page_chirho
        .match_indices(&prefix_chirho)
        .map(|(index_chirho, _match_chirho)| {
            let rest_chirho = &page_chirho[index_chirho + prefix_chirho.len()..];
            rest_chirho[..rest_chirho.find('"').expect("closing quote")].to_string()
        })
        .collect()
}

#[test]
fn every_empty_placeholder_gets_its_own_fresh_valid_key_chirho() {
    let page_chirho = format!(
        "<form>{FORM_CALLER_KEY_PLACEHOLDER_CHIRHO}Save</form><form>{FORM_CALLER_KEY_PLACEHOLDER_CHIRHO}Restore</form>\
         <form>{FORM_CALLER_KEY_PLACEHOLDER_CHIRHO}Restore</form>"
    );
    let issued_chirho = String::from_utf8(
        issue_caller_keys_into_placeholders_chirho(page_chirho.as_bytes())
            .expect("a page with placeholders is filled"),
    )
    .expect("utf8 page");
    assert!(!issued_chirho.contains(FORM_CALLER_KEY_PLACEHOLDER_CHIRHO));
    let keys_chirho = issued_keys_chirho(&issued_chirho);
    assert_eq!(keys_chirho.len(), 3, "one key per placeholder");
    let mut distinct_chirho = keys_chirho.clone();
    distinct_chirho.sort();
    distinct_chirho.dedup();
    assert_eq!(
        distinct_chirho.len(),
        3,
        "each placeholder gets its OWN key"
    );
    for key_chirho in &keys_chirho {
        assert_eq!(key_chirho.len(), 43, "32 random bytes in base64url");
        assert!(key_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_alphanumeric()
                || byte_chirho == b'_'
                || byte_chirho == b'-'));
        assert!(CallerIdempotencyKeyChirho::new_chirho(key_chirho.clone()).is_ok());
    }
    assert!(issued_chirho.starts_with("<form>") && issued_chirho.ends_with("Restore</form>"));
}

#[test]
fn a_page_without_a_placeholder_is_served_as_rendered_and_escaped_text_never_matches_chirho() {
    assert_eq!(
        issue_caller_keys_into_placeholders_chirho(b"<p>no forms here</p>"),
        None
    );
    // Customer text is escaped by the product's templates, so only the template's literal matches.
    let escaped_chirho =
        b"<p>&#60;input type=&#34;hidden&#34; name=&#34;idempotency_key_chirho&#34; value=&#34;&#34;&#62;</p>";
    assert_eq!(
        issue_caller_keys_into_placeholders_chirho(escaped_chirho),
        None
    );
}

#[test]
fn a_form_carries_its_key_exactly_once_and_the_run_sees_the_stripped_body_chirho() {
    let body_chirho =
        b"title_chirho=A+cafe%26bar&idempotency_key_chirho=k-one-chirho&note_chirho=x";
    let reading_chirho =
        read_caller_key_chirho(&form_headers_chirho(), body_chirho).expect("one valid field");
    assert_eq!(
        reading_chirho.caller_key_chirho.as_str_chirho(),
        "k-one-chirho"
    );
    assert_eq!(
        reading_chirho.business_body_chirho.as_deref(),
        Some(&b"title_chirho=A+cafe%26bar&note_chirho=x"[..]),
        "the carrier field is gone and every other byte is verbatim"
    );
    // An equal header is allowed alongside the field.
    let with_equal_header_chirho = read_caller_key_chirho(
        &with_header_key_chirho(form_headers_chirho(), "k-one-chirho"),
        body_chirho,
    )
    .expect("an equal header is fine");
    assert_eq!(
        with_equal_header_chirho.caller_key_chirho.as_str_chirho(),
        "k-one-chirho"
    );
    // An encoded spelling of the field name is still the field, and still stripped.
    let encoded_chirho = read_caller_key_chirho(
        &form_headers_chirho(),
        b"idempotency%5Fkey_chirho=k-two-chirho&a=1",
    )
    .expect("encoded name read");
    assert_eq!(
        encoded_chirho.caller_key_chirho.as_str_chirho(),
        "k-two-chirho"
    );
    assert_eq!(
        encoded_chirho.business_body_chirho.as_deref(),
        Some(&b"a=1"[..])
    );
}

#[test]
fn every_malformed_form_key_is_refused_before_any_run_chirho() {
    let cases_chirho: [(&[u8], CallerKeyCarrierRefusalChirho); 4] = [
        (b"a=1", CallerKeyCarrierRefusalChirho::FieldMissingChirho),
        (
            b"idempotency_key_chirho=one&idempotency_key_chirho=two",
            CallerKeyCarrierRefusalChirho::FieldDuplicateChirho,
        ),
        (
            b"idempotency_key_chirho=&a=1",
            CallerKeyCarrierRefusalChirho::FieldEmptyChirho,
        ),
        (
            b"idempotency_key_chirho=has%20space",
            CallerKeyCarrierRefusalChirho::FieldInvalidChirho,
        ),
    ];
    for (body_chirho, expected_chirho) in cases_chirho {
        assert_eq!(
            read_caller_key_chirho(&form_headers_chirho(), body_chirho).unwrap_err(),
            expected_chirho,
            "body {:?}",
            String::from_utf8_lossy(body_chirho)
        );
    }
    assert_eq!(
        read_caller_key_chirho(
            &with_header_key_chirho(form_headers_chirho(), "k-header-chirho"),
            b"idempotency_key_chirho=k-field-chirho"
        )
        .unwrap_err(),
        CallerKeyCarrierRefusalChirho::HeaderFieldMismatchChirho,
        "a header and a field that disagree must refuse"
    );
    let doubled_header_chirho = with_header_key_chirho(
        with_header_key_chirho(form_headers_chirho(), "k-a-chirho"),
        "k-a-chirho",
    );
    assert_eq!(
        read_caller_key_chirho(&doubled_header_chirho, b"idempotency_key_chirho=k-a-chirho")
            .unwrap_err(),
        CallerKeyCarrierRefusalChirho::HeaderDuplicateChirho
    );
}

#[test]
fn a_scripted_form_with_the_header_alone_keeps_the_one_header_rule_chirho() {
    // The R2-4 and F5 drills POST a url-encoded spend body with only the header.
    let body_chirho = b"item_chirho=render-run-chirho&concurrency_token_chirho=ab";
    let reading_chirho = read_caller_key_chirho(
        &with_header_key_chirho(form_headers_chirho(), "k-drill-chirho"),
        body_chirho,
    )
    .expect("the header carries the key when the form has no field");
    assert_eq!(
        reading_chirho.caller_key_chirho.as_str_chirho(),
        "k-drill-chirho"
    );
    assert_eq!(
        reading_chirho.business_body_chirho, None,
        "with no field there is nothing to strip, so the body runs exactly as sent"
    );
    // An empty placeholder is a field: the header does not rescue it.
    assert_eq!(
        read_caller_key_chirho(
            &with_header_key_chirho(form_headers_chirho(), "k-drill-chirho"),
            b"idempotency_key_chirho=&item_chirho=x",
        )
        .unwrap_err(),
        CallerKeyCarrierRefusalChirho::FieldEmptyChirho
    );
    // An invalid header with no field is the header's refusal.
    let mut bad_header_chirho = form_headers_chirho();
    bad_header_chirho.append(
        CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("has space"),
    );
    assert_eq!(
        read_caller_key_chirho(&bad_header_chirho, b"a=1").unwrap_err(),
        CallerKeyCarrierRefusalChirho::HeaderInvalidChirho
    );
}

#[test]
fn multipart_is_refused_even_with_a_header_and_never_falls_through_chirho() {
    let mut multipart_chirho = HeaderMap::new();
    multipart_chirho.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("multipart/form-data; boundary=x-chirho"),
    );
    let with_header_chirho = with_header_key_chirho(multipart_chirho, "k-multipart-chirho");
    assert_eq!(
        read_caller_key_chirho(&with_header_chirho, b"--x-chirho\r\n").unwrap_err(),
        CallerKeyCarrierRefusalChirho::MultipartNotYetCarriedChirho,
        "a multipart form must not take the header-only path with its field unstripped"
    );
    assert!(
        !is_browser_form_submission_chirho(&with_header_chirho),
        "a caller that sends the header is a script, not a browser"
    );
}

#[test]
fn a_non_form_caller_keeps_the_one_header_rule_chirho() {
    let json_chirho = with_header_key_chirho(HeaderMap::new(), "k-json-chirho");
    let reading_chirho = read_caller_key_chirho(&json_chirho, br#"{"a":1}"#).expect("header key");
    assert_eq!(
        reading_chirho.caller_key_chirho.as_str_chirho(),
        "k-json-chirho"
    );
    assert_eq!(
        reading_chirho.business_body_chirho, None,
        "a non-form body is not rewritten"
    );
    assert_eq!(
        read_caller_key_chirho(&HeaderMap::new(), b"{}").unwrap_err(),
        CallerKeyCarrierRefusalChirho::HeaderMissingChirho
    );
    assert!(!is_browser_form_submission_chirho(&json_chirho));
}

#[test]
fn strip_removes_every_spelling_of_the_field_and_preserves_business_bytes_chirho() {
    assert_eq!(
        strip_form_caller_key_chirho(
            b"idempotency_key_chirho=a&description_chirho=A+cozy+cafe%2C+daily"
        ),
        b"description_chirho=A+cozy+cafe%2C+daily"
    );
    assert_eq!(
        strip_form_caller_key_chirho(b"description_chirho=Zzyzx&idempotency_key_chirho=b"),
        b"description_chirho=Zzyzx"
    );
    assert_eq!(
        strip_form_caller_key_chirho(b"idempotency%5Fkey_chirho=c&d=1&idempotency_key_chirho=e"),
        b"d=1"
    );
    assert_eq!(
        strip_form_caller_key_chirho(b"description_chirho=A%26B&idempotency_key_chirho=f"),
        b"description_chirho=A%26B",
        "an encoded ampersand in a value is not a delimiter"
    );
    assert_eq!(strip_form_caller_key_chirho(b"a=1&b=2"), b"a=1&b=2");
}

#[test]
fn the_relay_classification_picks_the_token_never_a_string_chirho() {
    use RelayExecutionKnowledgeChirho::{DefinitelyNotExecutedChirho, MayHaveExecutedChirho};
    use RelayRefusalIdentityChirho::{
        RelayCallerKeyCollisionChirho, RelayCallerKeyInvalidChirho,
        RelayLocalAuthorityUnavailableChirho, RelayOwnerUnavailableChirho,
    };
    assert_eq!(
        form_refusal_token_chirho(RelayCallerKeyInvalidChirho, DefinitelyNotExecutedChirho),
        REFUSAL_CALLER_KEY_INVALID_CHIRHO
    );
    assert_eq!(
        form_refusal_token_chirho(RelayCallerKeyCollisionChirho, DefinitelyNotExecutedChirho),
        REFUSAL_CALLER_KEY_CONFLICT_CHIRHO
    );
    assert_eq!(
        form_refusal_token_chirho(
            RelayLocalAuthorityUnavailableChirho,
            DefinitelyNotExecutedChirho
        ),
        REFUSAL_WRITE_UNAVAILABLE_CHIRHO
    );
    assert_eq!(
        form_refusal_token_chirho(RelayOwnerUnavailableChirho, MayHaveExecutedChirho),
        REFUSAL_WRITE_OUTCOME_UNKNOWN_CHIRHO
    );
}

#[test]
fn a_refused_form_returns_only_to_a_landing_route_of_this_app_chirho() {
    let landing_chirho = |route_chirho: &str| route_chirho == "edit-page-chirho";
    let host_chirho = HeaderValue::from_static("perffection.example");
    let location_chirho = |referer_chirho: &'static str| {
        form_refusal_location_chirho(
            "pfe-chirho",
            Some(&HeaderValue::from_static(referer_chirho)),
            Some(&host_chirho),
            landing_chirho,
        )
    };
    let home_chirho = "/app-chirho/pfe-chirho/";
    assert_eq!(
        location_chirho("/app-chirho/pfe-chirho/edit-page-chirho"),
        "/app-chirho/pfe-chirho/edit-page-chirho"
    );
    assert_eq!(
        location_chirho(
            "https://perffection.example/app-chirho/pfe-chirho/edit-page-chirho?draft=1#x"
        ),
        "/app-chirho/pfe-chirho/edit-page-chirho",
        "same origin, with the query and fragment never carried"
    );
    for refused_chirho in [
        "https://evil.example/app-chirho/pfe-chirho/edit-page-chirho",
        "/app-chirho/pfe-chirho/not-declared-chirho",
        "/app-chirho/other-app-chirho/edit-page-chirho",
        "/app-chirho/pfe-chirho/edit-page-chirho/deeper",
        "//evil.example/app-chirho/pfe-chirho/edit-page-chirho",
        "/app-chirho/pfe-chirho/edit-page-chirho\\x",
        "/app-chirho/pfe-chirho/Edit-Page-chirho",
        "relative/app-chirho/pfe-chirho/edit-page-chirho",
    ] {
        assert_eq!(
            location_chirho(refused_chirho),
            home_chirho,
            "{refused_chirho}"
        );
    }
    assert_eq!(location_chirho(home_chirho), home_chirho);
    assert_eq!(
        form_refusal_location_chirho("pfe-chirho", None, Some(&host_chirho), landing_chirho),
        home_chirho
    );
}

#[test]
fn the_form_refusal_is_a_no_store_303_naming_its_token_chirho() {
    let response_chirho = form_refusal_response_chirho(
        "/app-chirho/pfe-chirho/edit-page-chirho",
        REFUSAL_CALLER_KEY_CONFLICT_CHIRHO,
    );
    assert_eq!(response_chirho.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response_chirho.headers().get(header::LOCATION).unwrap(),
        "/app-chirho/pfe-chirho/edit-page-chirho#refusal-caller-key-conflict-chirho"
    );
    assert_eq!(
        response_chirho
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap(),
        "private, no-store"
    );
}

#[test]
fn a_browser_form_is_a_form_body_with_no_caller_key_header_chirho() {
    assert!(is_browser_form_submission_chirho(&form_headers_chirho()));
    let mut multipart_chirho = HeaderMap::new();
    multipart_chirho.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("multipart/form-data; boundary=x-chirho"),
    );
    assert!(is_browser_form_submission_chirho(&multipart_chirho));
    assert!(!is_browser_form_submission_chirho(&with_header_key_chirho(
        form_headers_chirho(),
        "k-drill-chirho"
    )));
    assert!(!is_browser_form_submission_chirho(&HeaderMap::new()));
}

fn html_answer_chirho(body_chirho: Vec<u8>) -> Response {
    let mut response_chirho = Response::new(Body::from(body_chirho));
    response_chirho.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response_chirho
}

async fn answer_text_chirho(response_chirho: Response) -> String {
    let bytes_chirho = to_bytes(response_chirho.into_body(), usize::MAX)
        .await
        .expect("in-memory body");
    String::from_utf8(bytes_chirho.to_vec()).expect("utf8 page")
}

#[tokio::test]
async fn an_html_answer_gets_fresh_keys_and_is_never_cached_chirho() {
    let page_chirho = format!(
        "<form>{FORM_CALLER_KEY_PLACEHOLDER_CHIRHO}Save</form><form>{FORM_CALLER_KEY_PLACEHOLDER_CHIRHO}Restore</form>"
    );
    let mut answer_chirho = html_answer_chirho(page_chirho.clone().into_bytes());
    answer_chirho
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(page_chirho.len()));
    answer_chirho.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_static("\"rendered-chirho\""),
    );
    assert!(answer_is_html_chirho(&answer_chirho));
    let issued_chirho = issue_caller_keys_into_answer_chirho(answer_chirho).await;
    assert_eq!(
        issued_chirho.headers().get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    assert!(issued_chirho
        .headers()
        .get(header::CONTENT_LENGTH)
        .is_none());
    assert!(issued_chirho.headers().get(header::ETAG).is_none());
    let text_chirho = answer_text_chirho(issued_chirho).await;
    assert!(!text_chirho.contains(FORM_CALLER_KEY_PLACEHOLDER_CHIRHO));
    let keys_chirho = issued_keys_chirho(&text_chirho);
    assert_eq!(keys_chirho.len(), 2);
    assert_ne!(keys_chirho[0], keys_chirho[1]);
}

#[tokio::test]
async fn a_page_with_no_placeholder_or_too_large_passes_through_untouched_chirho() {
    let plain_chirho =
        issue_caller_keys_into_answer_chirho(html_answer_chirho(b"<p>no forms</p>".to_vec())).await;
    assert!(plain_chirho.headers().get(header::CACHE_CONTROL).is_none());
    assert_eq!(answer_text_chirho(plain_chirho).await, "<p>no forms</p>");
    let mut large_chirho = FORM_CALLER_KEY_PLACEHOLDER_CHIRHO.as_bytes().to_vec();
    large_chirho.resize(ISSUANCE_PAGE_MAX_BYTES_CHIRHO + 1, b' ');
    let skipped_chirho =
        issue_caller_keys_into_answer_chirho(html_answer_chirho(large_chirho)).await;
    assert!(skipped_chirho
        .headers()
        .get(header::CACHE_CONTROL)
        .is_none());
    assert!(
        answer_text_chirho(skipped_chirho)
            .await
            .starts_with(FORM_CALLER_KEY_PLACEHOLDER_CHIRHO),
        "an over-bound page is served as rendered, its placeholder empty"
    );
    let mut json_chirho = Response::new(Body::from("{}"));
    json_chirho.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    assert!(!answer_is_html_chirho(&json_chirho));
    let mut octet_chirho = Response::new(Body::from(FORM_CALLER_KEY_PLACEHOLDER_CHIRHO));
    octet_chirho.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    assert!(
        !answer_is_html_chirho(&octet_chirho),
        "an undeclared route's octet-stream answer is never rewritten"
    );
}

#[test]
fn a_refused_browser_form_goes_back_to_its_declared_page_chirho() {
    let mut headers_chirho = form_headers_chirho();
    headers_chirho.insert(
        header::REFERER,
        HeaderValue::from_static("/app-chirho/pfe-chirho/edit-page-chirho?x=1"),
    );
    let response_chirho = browser_form_refusal_response_chirho(
        &headers_chirho,
        "pfe-chirho",
        |route_chirho| route_chirho == "edit-page-chirho",
        REFUSAL_WRITE_UNAVAILABLE_CHIRHO,
    );
    assert_eq!(response_chirho.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response_chirho.headers().get(header::LOCATION).unwrap(),
        "/app-chirho/pfe-chirho/edit-page-chirho#refusal-write-unavailable-chirho"
    );
}
