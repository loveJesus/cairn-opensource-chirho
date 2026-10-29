// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K2's unit arms: the layer replaces any caching on an unmarked answer with one `private, no-store` and keeps a marked
//! answer's own, and a census pins every caller of the two public markers to the reviewed list.

use super::*;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn finalize_chirho(response_chirho: Response) -> Response {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(finalize_answer_cache_chirho(response_chirho))
}

fn cache_values_chirho(response_chirho: &Response) -> Vec<String> {
    response_chirho
        .headers()
        .get_all(CACHE_CONTROL)
        .iter()
        .map(|value_chirho| value_chirho.to_str().unwrap().to_string())
        .collect()
}

#[test]
fn an_unmarked_answer_leaves_with_exactly_one_private_no_store_whatever_it_carried_chirho() {
    // None at all.
    let bare_chirho = finalize_chirho(StatusCode::OK.into_response());
    assert_eq!(
        cache_values_chirho(&bare_chirho),
        [PRIVATE_ANSWER_CACHE_CONTROL_CHIRHO]
    );
    // A handler's public header is no permission: it is replaced, every value of it.
    let mut claimed_chirho = StatusCode::OK.into_response();
    claimed_chirho.headers_mut().append(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    claimed_chirho
        .headers_mut()
        .append(CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
    let claimed_chirho = finalize_chirho(claimed_chirho);
    assert_eq!(
        cache_values_chirho(&claimed_chirho),
        [PRIVATE_ANSWER_CACHE_CONTROL_CHIRHO]
    );
    // A refusal too.
    let refusal_chirho = finalize_chirho(StatusCode::NOT_FOUND.into_response());
    assert_eq!(
        cache_values_chirho(&refusal_chirho),
        [PRIVATE_ANSWER_CACHE_CONTROL_CHIRHO]
    );
}

#[test]
fn a_marked_answer_keeps_its_handlers_own_caching_or_none_chirho() {
    let mut immutable_chirho = StatusCode::OK.into_response();
    immutable_chirho.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    let immutable_chirho = finalize_chirho(public_answer_chirho(immutable_chirho));
    assert_eq!(
        cache_values_chirho(&immutable_chirho),
        ["public, max-age=31536000, immutable"]
    );
    let bare_chirho = finalize_chirho(public_answer_chirho(StatusCode::OK.into_response()));
    assert!(cache_values_chirho(&bare_chirho).is_empty());
}

/// Every production `.rs` file under the serve runtime's `src`, test files excluded, with its text.
fn production_sources_chirho() -> Vec<(String, String)> {
    let src_chirho = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut pending_chirho: Vec<PathBuf> = vec![src_chirho.clone()];
    let mut sources_chirho = Vec::new();
    while let Some(dir_chirho) = pending_chirho.pop() {
        for entry_chirho in std::fs::read_dir(&dir_chirho).unwrap() {
            let path_chirho = entry_chirho.unwrap().path();
            let name_chirho = path_chirho
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            if path_chirho.is_dir() {
                if name_chirho != "tests_chirho" {
                    pending_chirho.push(path_chirho);
                }
            } else if name_chirho.ends_with(".rs") && !name_chirho.ends_with("tests_chirho.rs") {
                let relative_chirho = path_chirho
                    .strip_prefix(&src_chirho)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                sources_chirho.push((
                    relative_chirho,
                    std::fs::read_to_string(&path_chirho).unwrap(),
                ));
            }
        }
    }
    sources_chirho
}

/// Per file, the calls of `name_chirho(` that are not its definition.
fn caller_census_chirho(
    sources_chirho: &[(String, String)],
    name_chirho: &str,
) -> BTreeMap<String, usize> {
    let call_chirho = format!("{name_chirho}(");
    let definition_chirho = format!("fn {name_chirho}(");
    let mut census_chirho = BTreeMap::new();
    for (file_chirho, text_chirho) in sources_chirho {
        let calls_chirho = text_chirho.matches(&call_chirho).count()
            - text_chirho.matches(&definition_chirho).count();
        if calls_chirho > 0 {
            census_chirho.insert(file_chirho.clone(), calls_chirho);
        }
    }
    census_chirho
}

#[test]
fn every_public_answer_is_a_reviewed_caller_of_the_two_markers_chirho() {
    let sources_chirho = production_sources_chirho();
    // The instrument's positive controls: it read the serve runtime's router, its public routes and its app road, and
    // (below) it finds both definitions.
    for known_chirho in [
        "serve_chirho.rs",
        "serve_chirho/public_routes_chirho.rs",
        "serve_chirho/runtime_web_chirho/app_http_chirho.rs",
    ] {
        assert!(
            sources_chirho
                .iter()
                .any(|(file_chirho, _)| file_chirho == known_chirho),
            "the census did not read {known_chirho}"
        );
    }
    let defined_chirho = |name_chirho: &str| {
        sources_chirho
            .iter()
            .filter(|(_, text_chirho)| text_chirho.contains(&format!("fn {name_chirho}(")))
            .count()
    };
    assert_eq!(defined_chirho("public_answer_chirho"), 1);
    assert_eq!(defined_chirho("public_app_answer_if_anonymous_chirho"), 1);

    // A new public answer is a review decision: add it here with its reason, never by accident.
    let reviewed_public_chirho = BTreeMap::from([
        // The landing page, the static scripts and demo pages, the runtime package artifacts and demo, and the public
        // API descriptors (descriptor, docs, app MCP, platform MCP), each on its success branch only.
        ("serve_chirho/public_routes_chirho.rs".to_string(), 15),
        // A static asset by hash (public, immutable) and by name (its no-store redirect).
        (
            "serve_chirho/app_web_chirho/app_assets_chirho.rs".to_string(),
            2,
        ),
        // The anonymous-public-app rule's own mark.
        (
            "serve_chirho/runtime_web_chirho/answer_cache_chirho.rs".to_string(),
            1,
        ),
    ]);
    assert_eq!(
        caller_census_chirho(&sources_chirho, "public_answer_chirho"),
        reviewed_public_chirho
    );
    // The app road's two GETs, the root and a named route.
    let reviewed_app_chirho = BTreeMap::from([
        (
            "serve_chirho/app_web_chirho/app_root_chirho.rs".to_string(),
            1,
        ),
        (
            "serve_chirho/runtime_web_chirho/app_http_chirho.rs".to_string(),
            1,
        ),
    ]);
    assert_eq!(
        caller_census_chirho(&sources_chirho, "public_app_answer_if_anonymous_chirho"),
        reviewed_app_chirho
    );
}
