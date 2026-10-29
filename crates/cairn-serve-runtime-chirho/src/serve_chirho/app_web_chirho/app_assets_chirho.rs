// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Same-origin static app asset routes over verified app asset records.

use super::answer_cache_chirho::public_answer_chirho;
use super::AppStateChirho;
use axum::extract::{Path as AxPath, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, LOCATION};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use cairn_chirho::app_chirho;
use cairn_chirho::model_chirho::HashChirho;

pub(super) type AppStaticAssetSelectionChirho = app_chirho::AppStaticAssetSelectionChirho;

pub(super) fn app_static_asset_by_name_for_root_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    name_chirho: &str,
) -> anyhow::Result<Option<AppStaticAssetSelectionChirho>> {
    app_chirho::app_static_asset_by_name_chirho(root_chirho, app_chirho, name_chirho)
}

pub(super) fn app_static_asset_by_hash_for_root_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    asset_chirho: &HashChirho,
) -> anyhow::Result<Option<AppStaticAssetSelectionChirho>> {
    app_chirho::app_static_asset_by_hash_chirho(root_chirho, app_chirho, asset_chirho)
}

pub(super) fn app_static_asset_bytes_for_root_chirho(
    root_chirho: &std::path::Path,
    selection_chirho: &AppStaticAssetSelectionChirho,
) -> anyhow::Result<Vec<u8>> {
    app_chirho::app_static_asset_bytes_chirho(root_chirho, selection_chirho)
}

pub(super) async fn app_asset_by_name_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    AxPath((app_chirho, name_chirho)): AxPath<(String, String)>,
) -> Response {
    let selection_chirho = match state_chirho
        .runtime_chirho
        .app_static_asset_by_name_chirho(&app_chirho, &name_chirho)
    {
        Ok(Some(selection_chirho)) => selection_chirho,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let location_chirho = format!(
        "/app-assets-chirho/{}/by-hash-chirho/{}/{}",
        percent_encode_path_segment_chirho(&selection_chirho.record_chirho.app_chirho),
        selection_chirho.record_chirho.asset_chirho.0,
        percent_encode_path_segment_chirho(&selection_chirho.record_chirho.name_chirho)
    );
    let mut response_chirho = StatusCode::FOUND.into_response();
    let headers_chirho = response_chirho.headers_mut();
    match HeaderValue::from_str(&location_chirho) {
        Ok(location_chirho) => {
            headers_chirho.insert(LOCATION, location_chirho);
            headers_chirho.insert(
                CACHE_CONTROL,
                HeaderValue::from_static("no-store, max-age=0"),
            );
            public_answer_chirho(response_chirho)
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub(super) async fn app_asset_by_hash_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    AxPath((app_chirho, hash_chirho, name_chirho)): AxPath<(String, String, String)>,
) -> Response {
    if app_chirho::validate_app_static_asset_name_chirho(&name_chirho).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(asset_chirho) = route_hash_chirho(&hash_chirho) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let selection_chirho = match state_chirho
        .runtime_chirho
        .app_static_asset_by_hash_chirho(&app_chirho, &asset_chirho)
    {
        Ok(Some(selection_chirho)) => selection_chirho,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let bytes_chirho = match state_chirho
        .runtime_chirho
        .app_static_asset_bytes_chirho(&selection_chirho)
    {
        Ok(bytes_chirho) => bytes_chirho,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut response_chirho = (StatusCode::OK, bytes_chirho).into_response();
    let headers_chirho = response_chirho.headers_mut();
    match HeaderValue::from_str(&selection_chirho.record_chirho.content_type_chirho) {
        Ok(content_type_chirho) => {
            headers_chirho.insert(CONTENT_TYPE, content_type_chirho);
            headers_chirho.insert(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );
            headers_chirho.insert(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            );
            if selection_chirho.record_chirho.content_type_chirho
                == app_chirho::APP_STATIC_ASSET_PDF_CONTENT_TYPE_CHIRHO
            {
                let disposition_chirho = format!(
                    "attachment; filename=\"{}\"",
                    selection_chirho.record_chirho.name_chirho
                );
                match HeaderValue::from_str(&disposition_chirho) {
                    Ok(disposition_chirho) => {
                        headers_chirho.insert(CONTENT_DISPOSITION, disposition_chirho);
                    }
                    Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            }
            public_answer_chirho(response_chirho)
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn route_hash_chirho(hash_chirho: &str) -> Option<HashChirho> {
    if hash_chirho.len() == 64
        && hash_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit())
    {
        Some(HashChirho(hash_chirho.to_ascii_lowercase()))
    } else {
        None
    }
}

fn percent_encode_path_segment_chirho(segment_chirho: &str) -> String {
    let mut encoded_chirho = String::new();
    for byte_chirho in segment_chirho.bytes() {
        if byte_chirho.is_ascii_alphanumeric()
            || byte_chirho == b'-'
            || byte_chirho == b'_'
            || byte_chirho == b'.'
            || byte_chirho == b'~'
        {
            encoded_chirho.push(byte_chirho as char);
        } else {
            encoded_chirho.push_str(&format!("%{byte_chirho:02X}"));
        }
    }
    encoded_chirho
}
