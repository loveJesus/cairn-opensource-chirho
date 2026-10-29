// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::{
    app_selection_error_response_chirho, direct_app_rejects_request_body_chirho,
    pre_body_request_access_refusal_chirho, read_served_app_request_body_chirho,
    run_app_http_with_method_for_served_request_chirho,
    write_relay_chirho::local_pre_body_route_policy_applies_chirho, AppStateChirho,
};
#[cfg(test)]
use axum::body::Bytes;
use axum::{
    body::Body,
    extract::{ConnectInfo, Path as AxPath, State},
    http::{header::LOCATION, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri},
    response::{IntoResponse, Response},
};

pub(super) async fn app_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    headers_chirho: HeaderMap,
    uri_chirho: Uri,
    AxPath(name_chirho): AxPath<String>,
) -> Response {
    if !uri_chirho.path().ends_with('/') {
        let mut response_chirho = StatusCode::PERMANENT_REDIRECT.into_response();
        let Ok(location_chirho) = HeaderValue::from_str(&format!("/app-chirho/{name_chirho}/"))
        else {
            return (StatusCode::BAD_REQUEST, "invalid app redirect location").into_response();
        };
        response_chirho
            .headers_mut()
            .insert(LOCATION, location_chirho);
        return response_chirho;
    }
    let response_chirho = run_app_http_with_method_for_served_request_chirho(
        &state_chirho,
        connect_info_chirho.map(|connect_info_chirho| connect_info_chirho.0),
        &headers_chirho,
        &name_chirho,
        None,
        Method::GET,
        Vec::new(),
    )
    .await;
    // K2: a public app's success to an anonymous GET stays public; every other answer is private.
    super::answer_cache_chirho::public_app_answer_if_anonymous_chirho(
        &state_chirho,
        &headers_chirho,
        &name_chirho,
        response_chirho,
    )
}

pub(super) async fn app_post_request_chirho(
    State(state_chirho): State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    headers_chirho: HeaderMap,
    AxPath(name_chirho): AxPath<String>,
    request_chirho: Request<Body>,
) -> Response {
    if local_pre_body_route_policy_applies_chirho(&state_chirho) {
        if let Some(response_chirho) = pre_body_request_access_refusal_chirho(
            &state_chirho,
            &headers_chirho,
            &name_chirho,
            None,
        ) {
            return response_chirho;
        }
        match direct_app_rejects_request_body_chirho(&state_chirho, &name_chirho) {
            Ok(true) => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
            Ok(false) => {}
            Err(error_chirho) => {
                return app_selection_error_response_chirho(error_chirho, &headers_chirho)
            }
        }
    }
    let body_chirho = match read_served_app_request_body_chirho(request_chirho).await {
        Ok(body_chirho) => body_chirho,
        Err(response_chirho) => return response_chirho,
    };
    run_app_http_with_method_for_served_request_chirho(
        &state_chirho,
        connect_info_chirho.map(|connect_info_chirho| connect_info_chirho.0),
        &headers_chirho,
        &name_chirho,
        None,
        Method::POST,
        body_chirho,
    )
    .await
}

#[cfg(test)]
pub(super) async fn app_post_chirho(
    state_chirho: State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    headers_chirho: HeaderMap,
    path_chirho: AxPath<String>,
    body_chirho: Bytes,
) -> Response {
    app_post_request_chirho(
        state_chirho,
        connect_info_chirho,
        headers_chirho,
        path_chirho,
        Request::new(Body::from(body_chirho)),
    )
    .await
}
