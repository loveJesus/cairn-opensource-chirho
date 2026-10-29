// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The browser caller-key carrier: one fresh key issued into each empty form placeholder after a
//! render, the key read back from a form body or the header, and a refused form POST answered in a
//! shape a browser can follow.
//!
//! A no-script form cannot set a header, so on an elected root a browser write carries its caller
//! idempotency key in the `idempotency_key_chirho` field instead. The product renders an EMPTY
//! placeholder per app-route POST form; the engine fills each one after the DAG has rendered, so
//! render inputs and run keys stay pure and nothing is stored per render. The contract is PFE's
//! `spec-chirho/workflows-chirho/platform-route-architecture-chirho/browser-caller-key-carrier-chirho.md`
//! (tokens final at PFE #28751; split agreed with gpt #28746 and #28889).
//!
//! Not yet carried: `multipart/form-data`. It is refused before any run rather than falling through to
//! the header-only rule with an unstripped field; its reader is the next brick.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/serve-write-forwarding-design-chirho.md`.

use axum::body::{to_bytes, Body, HttpBody as _};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use cairn_write_relay_chirho::{
    CallerIdempotencyKeyChirho, RelayExecutionKnowledgeChirho, RelayRefusalIdentityChirho,
    CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
};
use rand::RngCore;

/// The form field a browser write carries its caller key in.
pub(crate) const FORM_CALLER_KEY_FIELD_CHIRHO: &str = "idempotency_key_chirho";
/// The exact empty placeholder the product renders once per app-route POST form.
pub(crate) const FORM_CALLER_KEY_PLACEHOLDER_CHIRHO: &str =
    "<input type=\"hidden\" name=\"idempotency_key_chirho\" value=\"\">";

/// PFE's four refusal tokens for a form POST (#28751). They are the fixed part of the contract; the
/// words a page shows for each are the product's.
pub(crate) const REFUSAL_CALLER_KEY_INVALID_CHIRHO: &str = "caller-key-invalid-chirho";
pub(crate) const REFUSAL_CALLER_KEY_CONFLICT_CHIRHO: &str = "caller-key-conflict-chirho";
pub(crate) const REFUSAL_WRITE_UNAVAILABLE_CHIRHO: &str = "write-unavailable-chirho";
pub(crate) const REFUSAL_WRITE_OUTCOME_UNKNOWN_CHIRHO: &str = "write-outcome-unknown-chirho";

/// The largest rendered page the engine buffers to fill its placeholders. A larger page, or one whose size
/// is unknown, is served as rendered: its forms keep their empty placeholders and are refused before any
/// run, so issuance never fails an answer whose write may already have landed (PFE #28809).
const ISSUANCE_PAGE_MAX_BYTES_CHIRHO: usize = 8 * 1024 * 1024;

/// Random bytes behind one issued key: 32 bytes is 43 base64url characters, inside the 128-byte key
/// bound and drawn only from `[A-Za-z0-9_-]`, so form encoding never expands it.
const ISSUED_KEY_RANDOM_BYTES_CHIRHO: usize = 32;

/// One fresh, unpredictable caller key from the operating system's CSPRNG, or `None` if it failed.
pub(crate) fn issue_caller_key_chirho() -> Option<String> {
    let mut bytes_chirho = [0_u8; ISSUED_KEY_RANDOM_BYTES_CHIRHO];
    rand::rngs::OsRng.try_fill_bytes(&mut bytes_chirho).ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes_chirho))
}

/// Fill every exact empty placeholder in a rendered page with its own fresh key.
///
/// `None` means the page carried no placeholder and is served as rendered. Each placeholder gets a
/// distinct key, because one page can hold a Save and several Restores. If the CSPRNG fails, that
/// placeholder stays empty, so the POST it belongs to is refused before any run; issuance itself
/// never fails a page that has already been rendered.
pub(crate) fn issue_caller_keys_into_placeholders_chirho(payload_chirho: &[u8]) -> Option<Vec<u8>> {
    let placeholder_chirho = FORM_CALLER_KEY_PLACEHOLDER_CHIRHO.as_bytes();
    let mut rest_chirho = payload_chirho;
    let first_chirho = find_subslice_chirho(rest_chirho, placeholder_chirho)?;
    let mut out_chirho = Vec::with_capacity(payload_chirho.len() + 64);
    let mut next_chirho = Some(first_chirho);
    while let Some(index_chirho) = next_chirho {
        out_chirho.extend_from_slice(&rest_chirho[..index_chirho]);
        match issue_caller_key_chirho() {
            Some(key_chirho) => out_chirho.extend_from_slice(
                format!(
                    "<input type=\"hidden\" name=\"{FORM_CALLER_KEY_FIELD_CHIRHO}\" value=\"{key_chirho}\">"
                )
                .as_bytes(),
            ),
            None => out_chirho.extend_from_slice(placeholder_chirho),
        }
        rest_chirho = &rest_chirho[index_chirho + placeholder_chirho.len()..];
        next_chirho = find_subslice_chirho(rest_chirho, placeholder_chirho);
    }
    out_chirho.extend_from_slice(rest_chirho);
    Some(out_chirho)
}

/// Whether an answer is a `text/html` page, the only kind issuance looks inside. A route that declares no
/// response type answers `application/octet-stream`, which is never touched.
pub(crate) fn answer_is_html_chirho(response_chirho: &Response) -> bool {
    response_chirho
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value_chirho| value_chirho.to_str().ok())
        .is_some_and(|content_type_chirho| {
            content_type_chirho
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("text/html")
        })
}

/// Fill an html answer's empty placeholders with fresh keys, as the last step before it leaves.
///
/// A page that got keys is never cached, so no key is handed to two loads, and its length and entity tag
/// are dropped because its bytes changed. A page with no placeholder, or one too large or of unknown size,
/// passes through untouched.
pub(crate) async fn issue_caller_keys_into_answer_chirho(response_chirho: Response) -> Response {
    let bounded_chirho = response_chirho
        .body()
        .size_hint()
        .exact()
        .is_some_and(|size_chirho| size_chirho <= ISSUANCE_PAGE_MAX_BYTES_CHIRHO as u64);
    if !bounded_chirho {
        eprintln!("caller-key issuance skipped: the page's size is unknown or over the bound");
        return response_chirho;
    }
    let (mut parts_chirho, body_chirho) = response_chirho.into_parts();
    let bytes_chirho = match to_bytes(body_chirho, ISSUANCE_PAGE_MAX_BYTES_CHIRHO).await {
        Ok(bytes_chirho) => bytes_chirho,
        // The size was exact and within the bound, so an in-memory page cannot fail to read. If one
        // ever does, its bytes are gone, and a fixed refusal is better than a truncated page.
        Err(_error_chirho) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "error: CallerKeyIssuancePageUnreadableChirho\n",
            )
                .into_response()
        }
    };
    match issue_caller_keys_into_placeholders_chirho(&bytes_chirho) {
        Some(issued_chirho) => {
            parts_chirho.headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            );
            parts_chirho.headers.remove(header::CONTENT_LENGTH);
            parts_chirho.headers.remove(header::ETAG);
            Response::from_parts(parts_chirho, Body::from(issued_chirho))
        }
        None => Response::from_parts(parts_chirho, Body::from(bytes_chirho)),
    }
}

fn find_subslice_chirho(haystack_chirho: &[u8], needle_chirho: &[u8]) -> Option<usize> {
    haystack_chirho
        .windows(needle_chirho.len())
        .position(|window_chirho| window_chirho == needle_chirho)
}

/// Why a request's caller key could not be read. Every case is refused before any run as
/// `RelayCallerKeyInvalidChirho`; the cases are kept apart for tests and the server log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallerKeyCarrierRefusalChirho {
    HeaderMissingChirho,
    HeaderDuplicateChirho,
    HeaderInvalidChirho,
    FieldMissingChirho,
    FieldDuplicateChirho,
    FieldEmptyChirho,
    FieldInvalidChirho,
    HeaderFieldMismatchChirho,
    MultipartNotYetCarriedChirho,
}

/// A caller key read from one request, with the body the DAG must run on.
#[derive(Debug)]
pub(crate) struct CallerKeyReadingChirho {
    pub(crate) caller_key_chirho: CallerIdempotencyKeyChirho,
    /// The body with the carrier field removed, present only when the key came from a form. A run and
    /// its sealed input record never see the raw key; only its digest rides run identity.
    pub(crate) business_body_chirho: Option<Vec<u8>>,
}

/// Read the caller key from a form body or the header.
///
/// - A url-encoded form that carries the field must carry it exactly once, non-empty and valid. A
///   header alongside it must be equal.
/// - A url-encoded form with no field keeps the one-header rule. Scripted callers send a form body
///   with the header alone (the R2-4 and F5 geo drills do). A browser form cannot set the header, so
///   for a browser a missing field is still a missing key.
/// - A multipart form is refused for now (see the module header).
/// - Any other request must carry the header exactly once, as before the carrier existed.
pub(crate) fn read_caller_key_chirho(
    headers_chirho: &HeaderMap,
    body_chirho: &[u8],
) -> Result<CallerKeyReadingChirho, CallerKeyCarrierRefusalChirho> {
    let header_key_chirho = single_header_key_chirho(headers_chirho)?;
    match form_kind_chirho(headers_chirho) {
        FormKindChirho::MultipartChirho => {
            Err(CallerKeyCarrierRefusalChirho::MultipartNotYetCarriedChirho)
        }
        FormKindChirho::UrlEncodedChirho => {
            let mut field_values_chirho = url::form_urlencoded::parse(body_chirho)
                .filter(|(name_chirho, _value_chirho)| name_chirho == FORM_CALLER_KEY_FIELD_CHIRHO)
                .map(|(_name_chirho, value_chirho)| value_chirho.into_owned());
            let Some(value_chirho) = field_values_chirho.next() else {
                return header_only_reading_chirho(
                    header_key_chirho,
                    CallerKeyCarrierRefusalChirho::FieldMissingChirho,
                );
            };
            if field_values_chirho.next().is_some() {
                return Err(CallerKeyCarrierRefusalChirho::FieldDuplicateChirho);
            }
            if value_chirho.is_empty() {
                return Err(CallerKeyCarrierRefusalChirho::FieldEmptyChirho);
            }
            if let Some(header_value_chirho) = header_key_chirho {
                if header_value_chirho != value_chirho {
                    return Err(CallerKeyCarrierRefusalChirho::HeaderFieldMismatchChirho);
                }
            }
            let caller_key_chirho = CallerIdempotencyKeyChirho::new_chirho(value_chirho)
                .map_err(|_error_chirho| CallerKeyCarrierRefusalChirho::FieldInvalidChirho)?;
            Ok(CallerKeyReadingChirho {
                caller_key_chirho,
                business_body_chirho: Some(strip_form_caller_key_chirho(body_chirho)),
            })
        }
        FormKindChirho::NotFormChirho => header_only_reading_chirho(
            header_key_chirho,
            CallerKeyCarrierRefusalChirho::HeaderMissingChirho,
        ),
    }
}

/// The key from the header alone; the body runs exactly as sent.
fn header_only_reading_chirho(
    header_key_chirho: Option<String>,
    missing_chirho: CallerKeyCarrierRefusalChirho,
) -> Result<CallerKeyReadingChirho, CallerKeyCarrierRefusalChirho> {
    let header_value_chirho = header_key_chirho.ok_or(missing_chirho)?;
    let caller_key_chirho = CallerIdempotencyKeyChirho::new_chirho(header_value_chirho)
        .map_err(|_error_chirho| CallerKeyCarrierRefusalChirho::HeaderInvalidChirho)?;
    Ok(CallerKeyReadingChirho {
        caller_key_chirho,
        business_body_chirho: None,
    })
}

fn single_header_key_chirho(
    headers_chirho: &HeaderMap,
) -> Result<Option<String>, CallerKeyCarrierRefusalChirho> {
    let mut values_chirho = headers_chirho
        .get_all(CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO)
        .iter();
    let Some(value_chirho) = values_chirho.next() else {
        return Ok(None);
    };
    if values_chirho.next().is_some() {
        return Err(CallerKeyCarrierRefusalChirho::HeaderDuplicateChirho);
    }
    value_chirho
        .to_str()
        .map(|text_chirho| Some(text_chirho.to_string()))
        .map_err(|_error_chirho| CallerKeyCarrierRefusalChirho::HeaderInvalidChirho)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FormKindChirho {
    UrlEncodedChirho,
    MultipartChirho,
    NotFormChirho,
}

fn form_kind_chirho(headers_chirho: &HeaderMap) -> FormKindChirho {
    let Some(content_type_chirho) = headers_chirho
        .get(header::CONTENT_TYPE)
        .and_then(|value_chirho| value_chirho.to_str().ok())
    else {
        return FormKindChirho::NotFormChirho;
    };
    let media_type_chirho = content_type_chirho
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match media_type_chirho.as_str() {
        "application/x-www-form-urlencoded" => FormKindChirho::UrlEncodedChirho,
        "multipart/form-data" => FormKindChirho::MultipartChirho,
        _ => FormKindChirho::NotFormChirho,
    }
}

/// Whether a request is a browser form submission, which takes the 303 refusal shape: a form body with no
/// caller-key header. A no-script form cannot set that header, so a caller that sends it is a script and
/// keeps the plain refusal it reads today (the drills, the MCP adapter).
pub(crate) fn is_browser_form_submission_chirho(headers_chirho: &HeaderMap) -> bool {
    form_kind_chirho(headers_chirho) != FormKindChirho::NotFormChirho
        && !headers_chirho.contains_key(CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO)
}

/// Remove every `idempotency_key_chirho=<value>` pair from a url-encoded body, keeping every other
/// pair's bytes VERBATIM (only the `&` delimiters are rejoined). An encoded spelling of the field name
/// is still dropped, and an encoded `&` inside a value stays `%26`, so a value cannot smuggle a second
/// field out. The reader rejects a duplicate field before this runs; dropping all matches is defence
/// in depth.
pub(crate) fn strip_form_caller_key_chirho(body_chirho: &[u8]) -> Vec<u8> {
    let mut out_chirho: Vec<u8> = Vec::with_capacity(body_chirho.len());
    for segment_chirho in body_chirho.split(|byte_chirho| *byte_chirho == b'&') {
        let key_bytes_chirho = match segment_chirho
            .iter()
            .position(|byte_chirho| *byte_chirho == b'=')
        {
            Some(equals_chirho) => &segment_chirho[..equals_chirho],
            None => segment_chirho,
        };
        if urlencoded_name_equals_chirho(key_bytes_chirho, FORM_CALLER_KEY_FIELD_CHIRHO) {
            continue;
        }
        if !out_chirho.is_empty() {
            out_chirho.push(b'&');
        }
        out_chirho.extend_from_slice(segment_chirho);
    }
    out_chirho
}

/// Decode a url-encoded name (`+` is a space, `%XX` a byte, a malformed `%` stays literal) and compare
/// it to a plain-ASCII field name, with the same semantics `url::form_urlencoded` reads names with.
fn urlencoded_name_equals_chirho(raw_name_chirho: &[u8], field_name_chirho: &str) -> bool {
    let mut decoded_chirho: Vec<u8> = Vec::with_capacity(raw_name_chirho.len());
    let mut index_chirho = 0;
    while index_chirho < raw_name_chirho.len() {
        match raw_name_chirho[index_chirho] {
            b'+' => {
                decoded_chirho.push(b' ');
                index_chirho += 1;
            }
            b'%' if index_chirho + 2 < raw_name_chirho.len() => {
                match (
                    hex_nibble_chirho(raw_name_chirho[index_chirho + 1]),
                    hex_nibble_chirho(raw_name_chirho[index_chirho + 2]),
                ) {
                    (Some(high_chirho), Some(low_chirho)) => {
                        decoded_chirho.push(high_chirho * 16 + low_chirho);
                        index_chirho += 3;
                    }
                    _ => {
                        decoded_chirho.push(b'%');
                        index_chirho += 1;
                    }
                }
            }
            byte_chirho => {
                decoded_chirho.push(byte_chirho);
                index_chirho += 1;
            }
        }
    }
    decoded_chirho == field_name_chirho.as_bytes()
}

fn hex_nibble_chirho(byte_chirho: u8) -> Option<u8> {
    match byte_chirho {
        b'0'..=b'9' => Some(byte_chirho - b'0'),
        b'a'..=b'f' => Some(byte_chirho - b'a' + 10),
        b'A'..=b'F' => Some(byte_chirho - b'A' + 10),
        _ => None,
    }
}

/// The token a refused form POST names, chosen by the relay's own typed classification: the identity
/// for the two caller-key refusals, and the execution knowledge for everything else. This formats the
/// relay's verdict; it never classifies an error string.
pub(crate) fn form_refusal_token_chirho(
    identity_chirho: RelayRefusalIdentityChirho,
    knowledge_chirho: RelayExecutionKnowledgeChirho,
) -> &'static str {
    match (identity_chirho, knowledge_chirho) {
        (RelayRefusalIdentityChirho::RelayCallerKeyInvalidChirho, _) => {
            REFUSAL_CALLER_KEY_INVALID_CHIRHO
        }
        (RelayRefusalIdentityChirho::RelayCallerKeyCollisionChirho, _) => {
            REFUSAL_CALLER_KEY_CONFLICT_CHIRHO
        }
        (_, RelayExecutionKnowledgeChirho::MayHaveExecutedChirho) => {
            REFUSAL_WRITE_OUTCOME_UNKNOWN_CHIRHO
        }
        _ => REFUSAL_WRITE_UNAVAILABLE_CHIRHO,
    }
}

/// Where a refused form POST sends the browser: the page that rendered the form when the Referer names
/// one of this app's landing routes, else the app's home. A landing is declared by the app's route
/// table, takes no request body and answers HTML (PFE #29303, #29320); the caller's
/// `route_is_landing_chirho` decides it from verified records.
///
/// The Referer is only a lookup key. It must be this origin, one leading slash, no backslash, control
/// character, space or non-ASCII byte, and exactly `/app-chirho/<app>/<route>` with `route` a landing.
/// A query or fragment is never carried, and no header value is ever echoed into the answer.
pub(crate) fn form_refusal_location_chirho(
    app_name_chirho: &str,
    referer_chirho: Option<&HeaderValue>,
    host_chirho: Option<&HeaderValue>,
    route_is_landing_chirho: impl Fn(&str) -> bool,
) -> String {
    let home_chirho = format!("/app-chirho/{app_name_chirho}/");
    referer_chirho
        .and_then(|value_chirho| value_chirho.to_str().ok())
        .and_then(|referer_chirho| {
            landing_referer_path_chirho(
                referer_chirho,
                host_chirho,
                &home_chirho,
                &route_is_landing_chirho,
            )
        })
        .unwrap_or(home_chirho)
}

fn landing_referer_path_chirho(
    referer_chirho: &str,
    host_chirho: Option<&HeaderValue>,
    home_chirho: &str,
    route_is_landing_chirho: &impl Fn(&str) -> bool,
) -> Option<String> {
    let path_chirho = match referer_chirho
        .strip_prefix("https://")
        .or_else(|| referer_chirho.strip_prefix("http://"))
    {
        Some(after_scheme_chirho) => {
            let (authority_chirho, path_rest_chirho) = after_scheme_chirho.split_once('/')?;
            let host_chirho = host_chirho?.to_str().ok()?;
            if !authority_chirho.eq_ignore_ascii_case(host_chirho) {
                return None;
            }
            format!("/{path_rest_chirho}")
        }
        None => referer_chirho.to_string(),
    };
    let path_chirho = path_chirho.split(['?', '#']).next()?;
    if !path_chirho.starts_with('/')
        || path_chirho.starts_with("//")
        || path_chirho.bytes().any(|byte_chirho| {
            byte_chirho == b'\\'
                || byte_chirho == b' '
                || byte_chirho.is_ascii_control()
                || !byte_chirho.is_ascii()
        })
    {
        return None;
    }
    let route_chirho = path_chirho.strip_prefix(home_chirho)?;
    if route_chirho.is_empty() {
        return Some(home_chirho.to_string());
    }
    let route_shape_ok_chirho = route_chirho.bytes().all(|byte_chirho| {
        byte_chirho.is_ascii_lowercase()
            || byte_chirho.is_ascii_digit()
            || byte_chirho == b'-'
            || byte_chirho == b'_'
    });
    (route_shape_ok_chirho && route_is_landing_chirho(route_chirho))
        .then(|| format!("{home_chirho}{route_chirho}"))
}

/// The 303 a refused browser form gets: back to its own landing page, else the app's home.
pub(crate) fn browser_form_refusal_response_chirho(
    headers_chirho: &HeaderMap,
    app_name_chirho: &str,
    route_is_landing_chirho: impl Fn(&str) -> bool,
    token_chirho: &str,
) -> Response {
    let location_chirho = form_refusal_location_chirho(
        app_name_chirho,
        headers_chirho.get(header::REFERER),
        headers_chirho.get(header::HOST),
        route_is_landing_chirho,
    );
    form_refusal_response_chirho(&location_chirho, token_chirho)
}

/// The browser-readable refusal: a 303 to `location_chirho` with `#refusal-<token>`, never cached.
pub(crate) fn form_refusal_response_chirho(location_chirho: &str, token_chirho: &str) -> Response {
    let target_chirho = format!("{location_chirho}#refusal-{token_chirho}");
    match HeaderValue::from_str(&target_chirho) {
        Ok(location_value_chirho) => (
            StatusCode::SEE_OTHER,
            [
                (header::LOCATION, location_value_chirho),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("private, no-store"),
                ),
            ],
        )
            .into_response(),
        // The location is built only from fixed text and validated route bytes, so this cannot
        // happen; refusing plainly is still better than answering with a broken redirect.
        Err(_error_chirho) => {
            (StatusCode::BAD_REQUEST, format!("error: {token_chirho}\n")).into_response()
        }
    }
}

#[cfg(test)]
#[path = "caller_key_carrier_tests_chirho.rs"]
mod tests_chirho;
