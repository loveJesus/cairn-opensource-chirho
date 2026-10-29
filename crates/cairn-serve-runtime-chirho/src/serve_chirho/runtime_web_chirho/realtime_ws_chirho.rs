// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Authenticated fail-closed boundary for the retired realtime v1 money protocol.

use super::AppStateChirho;
use axum::{
    extract::{ws::WebSocketUpgrade, Path as AxPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use cairn_chirho::effect_chirho;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub(super) struct RealtimeWsQueryChirho {
    caller_chirho: String,
}

/// GET /realtime-chirho/:session_chirho/ws-chirho — authenticate, then refuse the retired v1
/// money protocol before session, effect, provider, or ledger work. Realtime v2 needs its own
/// reviewed ledger-substrate descriptor; caller input grants no interim authority.
pub(super) async fn realtime_ws_upgrade_chirho(
    _ws_chirho: WebSocketUpgrade,
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    AxPath(_session_chirho): AxPath<String>,
    Query(query_chirho): Query<RealtimeWsQueryChirho>,
) -> Response {
    let runtime_chirho = &state_chirho.runtime_chirho;
    if let Some(response_chirho) = runtime_chirho
        .require_principal_session_chirho(&headers_chirho, &query_chirho.caller_chirho)
    {
        return response_chirho;
    }

    let error_chirho = effect_chirho::refuse_legacy_realtime_money_road_chirho()
        .expect_err("the retired realtime v1 money protocol must refuse");
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "ok_chirho": false,
            "error_chirho": error_chirho.to_string(),
        })),
    )
        .into_response()
}
