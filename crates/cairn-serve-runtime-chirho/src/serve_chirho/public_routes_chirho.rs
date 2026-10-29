// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Public static and descriptor routes for the Cairn HTTP server.

use super::answer_cache_chirho::public_answer_chirho;
use super::{escape_html_chirho, parse_content_hash_chirho, AppStateChirho};
use axum::{
    extract::{Path as AxPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use cairn_chirho::{
    app_descriptor_chirho, app_docs_chirho, compile_chirho, platform_mcp_chirho,
    runtime_profile_chirho,
};

pub(super) type AppDescriptorChirho = app_descriptor_chirho::AppDescriptorChirho;
pub(super) type RuntimePackageChirho = runtime_profile_chirho::RuntimePackageChirho;

pub(super) fn validate_public_runtime_package_for_root_chirho(
    root_chirho: &std::path::Path,
    package_hash_chirho: &cairn_chirho::model_chirho::HashChirho,
) -> anyhow::Result<RuntimePackageChirho> {
    runtime_profile_chirho::validate_public_runtime_package_chirho(root_chirho, package_hash_chirho)
}

pub(super) fn public_runtime_package_executable_bytes_for_root_chirho(
    root_chirho: &std::path::Path,
    package_chirho: &RuntimePackageChirho,
) -> anyhow::Result<Vec<u8>> {
    Ok(cairn_chirho::cas_chirho::get_chirho(
        root_chirho,
        &package_chirho.executable_chirho,
    )?)
}

pub(super) fn public_app_descriptor_for_root_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
) -> anyhow::Result<Option<AppDescriptorChirho>> {
    app_descriptor_chirho::app_descriptor_chirho(root_chirho, app_chirho)
}

pub(super) async fn healthz_chirho() -> &'static str {
    "ok\n"
}

/// GET / — the platform landing page: what cairn is and where to look next.
/// Without it the root path 404s to a blank page.
pub(super) async fn index_chirho() -> Response {
    public_answer_chirho(
        (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            index_html_chirho(),
        )
            .into_response(),
    )
}

pub(super) fn index_html_chirho() -> String {
    String::from(
        "<!doctype html>\n<html lang=\"en\">\n<meta charset=\"utf-8\">\n\
	<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>cairn-chirho</title>\n\
<link rel=\"icon\" href=\"data:,\">\n\
<style>\n\
:root{color-scheme:light dark}\n\
body{font:16px/1.6 system-ui,-apple-system,sans-serif;max-width:46rem;margin:4rem auto;padding:0 1.25rem}\n\
h1{font-size:2rem;margin:.2em 0}\n\
h2{margin-top:2rem;font-size:1.05rem;opacity:.85}\n\
code{font-family:ui-monospace,SFMono-Regular,monospace}\n\
.h{opacity:.45;font:13px ui-monospace,monospace}\n\
a{color:#3b82f6;text-decoration:none}a:hover{text-decoration:underline}\n\
.lede{opacity:.82}\n\
footer{margin-top:3rem;opacity:.5;font-size:.85rem}\n\
ul{padding-left:1.2rem}\n\
</style>\n\
<body>\n\
	<h1>\u{1FAA8} cairn-chirho</h1>\n\
	<p class=\"lede\">A content-addressed, capability-secured, versioned dataflow DAG runtime. \
	Every node, input, and output is an immutable, hash-named stone &mdash; so caching, versioning, and audit are three views of one Merkle DAG, and rollback is just moving a ref.</p>\n\
	<p class=\"lede\">This public page intentionally omits deployed app inventory and owner metadata; the operator dashboard is admin-token gated.</p>\n\
	<h2>Explore</h2>\n<ul>\n\
	<li><a href=\"/dashboard-chirho\">/dashboard-chirho</a> &mdash; admin-token-gated operator diagnostics</li>\n\
<li><a href=\"/auth-chirho/register-chirho\">/auth-chirho/register-chirho</a> &mdash; public user registration, disabled unless a server registration token is configured</li>\n\
<li><a href=\"/client-demo-chirho\">/client-demo-chirho</a> &mdash; the reactive WASM client (a DAG compiled to wasm, rendering in the browser)</li>\n\
<li><a href=\"/contact-demo-chirho\">/contact-demo-chirho</a> &mdash; same-origin contact app page for a deployed PII-safe contact app</li>\n\
<li><a href=\"/perffection-intake-demo-chirho\">/perffection-intake-demo-chirho</a> &mdash; same-origin perffection intake app page for a deployed PII-safe dogfood app</li>\n\
<li><code>/runtime-package-demo-chirho/&lt;package_chirho&gt;</code> &mdash; browser loader for a validated RuntimePackageChirho artifact</li>\n\
<li><code>/runtime-package-chirho/&lt;package_chirho&gt;/manifest-chirho</code> &mdash; validated runtime package manifest + executable artifact delivery</li>\n\
<li><a href=\"/healthz-chirho\">/healthz-chirho</a> &mdash; liveness</li>\n\
</ul>\n\
<footer>&ldquo;&hellip; these stones shall be a memorial&hellip;&rdquo; &mdash; Joshua 4. Every object is a stone; the cairn is the history you can always return to.</footer>\n\
</body>\n</html>\n"
    )
}

pub(super) async fn runtime_package_manifest_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    AxPath(package_chirho): AxPath<String>,
) -> Response {
    let package_hash_chirho = match parse_content_hash_chirho(&package_chirho, "package_chirho") {
        Ok(hash_chirho) => hash_chirho,
        Err(e_chirho) => {
            return (StatusCode::BAD_REQUEST, format!("error: {e_chirho}\n")).into_response()
        }
    };
    match state_chirho
        .runtime_chirho
        .validate_public_runtime_package_chirho(&package_hash_chirho)
    {
        Ok(package_chirho) => public_answer_chirho(Json(package_chirho).into_response()),
        Err(e_chirho) => runtime_package_error_response_chirho(e_chirho),
    }
}

pub(super) async fn runtime_package_executable_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    AxPath(package_chirho): AxPath<String>,
) -> Response {
    let package_hash_chirho = match parse_content_hash_chirho(&package_chirho, "package_chirho") {
        Ok(hash_chirho) => hash_chirho,
        Err(e_chirho) => {
            return (StatusCode::BAD_REQUEST, format!("error: {e_chirho}\n")).into_response()
        }
    };
    let package_chirho = match state_chirho
        .runtime_chirho
        .validate_public_runtime_package_chirho(&package_hash_chirho)
    {
        Ok(package_chirho) => package_chirho,
        Err(e_chirho) => return runtime_package_error_response_chirho(e_chirho),
    };
    match state_chirho
        .runtime_chirho
        .public_runtime_package_executable_bytes_chirho(&package_chirho)
    {
        Ok(bytes_chirho) => public_answer_chirho(
            (
                [(axum::http::header::CONTENT_TYPE, "application/wasm")],
                bytes_chirho,
            )
                .into_response(),
        ),
        Err(e_chirho) => super::public_error_chirho::public_error_response_chirho(
            "runtime-package-executable-chirho",
            super::public_error_chirho::classify_non_dag_chirho(
                &e_chirho,
                StatusCode::NOT_FOUND,
                "runtime-package-executable-not-found-chirho",
            ),
            &axum::http::HeaderMap::new(),
            None,
        ),
    }
}

// An app's API surface is meant to be discoverable (like any API's docs/OpenAPI): the descriptor,
// Markdown reference, and MCP manifest carry only routes, input modes, response types, and the
// plain-language capability verdict — no secrets, no PII, no owner principal — so they are public
// read-only GETs that 404 when the app is not deployed and fail closed (500, no detail) on error.
pub(super) async fn app_descriptor_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    AxPath(app_chirho): AxPath<String>,
) -> Response {
    match state_chirho
        .runtime_chirho
        .public_app_descriptor_chirho(&app_chirho)
    {
        Ok(Some(descriptor_chirho)) => {
            public_answer_chirho(Json(descriptor_chirho).into_response())
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "descriptor unavailable").into_response(),
    }
}

pub(super) async fn app_docs_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    AxPath(app_chirho): AxPath<String>,
) -> Response {
    match state_chirho
        .runtime_chirho
        .public_app_descriptor_chirho(&app_chirho)
    {
        Ok(Some(descriptor_chirho)) => public_answer_chirho(
            (
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/markdown; charset=utf-8",
                )],
                app_docs_chirho::app_docs_markdown_chirho(&descriptor_chirho),
            )
                .into_response(),
        ),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "docs unavailable").into_response(),
    }
}

// The platform's own MCP tool catalog: a static, public read-only list of the owner tools an agent
// can drive, each mapping to an existing cairn command (no MCP-only authority). Discoverable like
// any tool catalog; no app/owner state, no secrets.
pub(super) async fn platform_mcp_get_chirho() -> Response {
    public_answer_chirho(Json(platform_mcp_chirho::platform_mcp_manifest_chirho()).into_response())
}

pub(super) async fn app_mcp_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    AxPath(app_chirho): AxPath<String>,
) -> Response {
    match state_chirho
        .runtime_chirho
        .public_app_descriptor_chirho(&app_chirho)
    {
        Ok(Some(descriptor_chirho)) => public_answer_chirho(
            Json(app_docs_chirho::app_mcp_manifest_chirho(&descriptor_chirho)).into_response(),
        ),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "mcp manifest unavailable",
        )
            .into_response(),
    }
}

const HOST_JS_CHIRHO: &str = include_str!("../../../../client-chirho/host-chirho.js");
const RUNTIME_PACKAGE_HOST_JS_CHIRHO: &str =
    include_str!("../../../../client-chirho/runtime-package-host-chirho.js");
const HTMX_LITE_JS_CHIRHO: &str = include_str!("../../../../client-chirho/htmx-lite-chirho.js");
const CLIENT_DEMO_HTML_CHIRHO: &str = include_str!("../../../../client-chirho/demo-chirho.html");
const CONTACT_DEMO_HTML_CHIRHO: &str =
    include_str!("../../../../examples-chirho/contact-persisting-page-chirho.html");
const PERFFECTION_INTAKE_DEMO_HTML_CHIRHO: &str =
    include_str!("../../../../examples-chirho/perffection-intake-page-chirho.html");

/// GET /host-chirho.js — the JS client host (bytes ABI).
pub(super) async fn host_js_chirho() -> Response {
    public_answer_chirho(
        (
            [(
                axum::http::header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            )],
            HOST_JS_CHIRHO,
        )
            .into_response(),
    )
}

/// GET /runtime-package-host-chirho.js — fetch + run RuntimePackageChirho artifacts in browser JS.
pub(super) async fn runtime_package_host_js_chirho() -> Response {
    public_answer_chirho(
        (
            [(
                axum::http::header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            )],
            RUNTIME_PACKAGE_HOST_JS_CHIRHO,
        )
            .into_response(),
    )
}

/// GET /htmx-lite-chirho.js — local same-origin htmx subset for example pages.
pub(super) async fn htmx_lite_js_chirho() -> Response {
    public_answer_chirho(
        (
            [(
                axum::http::header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            )],
            HTMX_LITE_JS_CHIRHO,
        )
            .into_response(),
    )
}

/// GET /client-demo-chirho — an HTML page that loads the host + a compiled DAG and runs it.
pub(super) async fn client_demo_chirho() -> Response {
    public_answer_chirho(
        (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            CLIENT_DEMO_HTML_CHIRHO,
        )
            .into_response(),
    )
}

/// GET /contact-demo-chirho — browser page for the PII-safe persisting contact app.
pub(super) async fn contact_demo_chirho() -> Response {
    public_answer_chirho(
        (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            CONTACT_DEMO_HTML_CHIRHO,
        )
            .into_response(),
    )
}

/// GET /perffection-intake-demo-chirho — browser page for the PII-safe perffection intake app.
pub(super) async fn perffection_intake_demo_chirho() -> Response {
    public_answer_chirho(
        (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            PERFFECTION_INTAKE_DEMO_HTML_CHIRHO,
        )
            .into_response(),
    )
}

/// GET /runtime-package-demo-chirho/:package — page that runs a delivered runtime package artifact.
pub(super) async fn runtime_package_demo_chirho(
    State(state_chirho): State<AppStateChirho>,
    AxPath(package_chirho): AxPath<String>,
) -> Response {
    let package_hash_chirho = match parse_content_hash_chirho(&package_chirho, "package_chirho") {
        Ok(hash_chirho) => hash_chirho,
        Err(e_chirho) => {
            return (StatusCode::BAD_REQUEST, format!("error: {e_chirho}\n")).into_response()
        }
    };
    if let Err(e_chirho) = state_chirho
        .runtime_chirho
        .validate_public_runtime_package_chirho(&package_hash_chirho)
    {
        return runtime_package_error_response_chirho(e_chirho);
    }
    public_answer_chirho(
        (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            runtime_package_demo_html_chirho(&package_hash_chirho.0),
        )
            .into_response(),
    )
}

fn runtime_package_demo_html_chirho(package_chirho: &str) -> String {
    format!(
        "<!doctype html>\n\
<!-- For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16 -->\n\
<meta charset=\"utf-8\">\n\
<title>cairn-chirho runtime package demo</title>\n\
<body>\n\
  <h1>cairn-chirho runtime package</h1>\n\
  <p>package: <code id=\"package-chirho\">{}</code></p>\n\
  <p>input: <code id=\"runtime-input-chirho\">hello, cairn</code></p>\n\
  <p>entry: <code id=\"runtime-entry-chirho\">...</code></p>\n\
  <p>output: <code id=\"runtime-output-chirho\">...</code></p>\n\
  <script type=\"module\">\n\
    import {{ fetchRuntimePackageChirho, runRuntimePackageTextChirho }} from \"/runtime-package-host-chirho.js\";\n\
    const packageChirho = document.getElementById(\"package-chirho\").textContent;\n\
    const inputChirho = document.getElementById(\"runtime-input-chirho\").textContent;\n\
    const artifactChirho = await fetchRuntimePackageChirho(packageChirho);\n\
    document.getElementById(\"runtime-entry-chirho\").textContent = artifactChirho.manifest_chirho.entry_chirho;\n\
    document.getElementById(\"runtime-output-chirho\").textContent = await runRuntimePackageTextChirho(packageChirho, inputChirho);\n\
  </script>\n\
</body>\n",
        escape_html_chirho(package_chirho)
    )
}

/// GET /wasm-demo-chirho — the demo composed chain (upcase->reverse), served as application/wasm.
pub(super) async fn wasm_demo_chirho() -> Response {
    match compile_chirho::demo_chain_wasm_chirho() {
        Ok(wasm_chirho) => public_answer_chirho(
            (
                [(axum::http::header::CONTENT_TYPE, "application/wasm")],
                wasm_chirho,
            )
                .into_response(),
        ),
        Err(e_chirho) => super::public_error_chirho::public_error_response_chirho(
            "wasm-demo-chirho",
            super::public_error_chirho::classify_non_dag_chirho(
                &e_chirho,
                StatusCode::INTERNAL_SERVER_ERROR,
                "wasm-demo-unavailable-chirho",
            ),
            &axum::http::HeaderMap::new(),
            None,
        ),
    }
}

/// A runtime package's public refusal: not found (its text read for that status only, as before) or not
/// public, by fixed identity; a typed resource exhaustion answers 503. No hash or record name is echoed.
fn runtime_package_error_response_chirho(error_chirho: anyhow::Error) -> Response {
    let message_chirho = error_chirho.to_string();
    let (status_chirho, identity_chirho) =
        if message_chirho.contains("not in store") || message_chirho.contains("not in the store") {
            (StatusCode::NOT_FOUND, "runtime-package-not-found-chirho")
        } else {
            (StatusCode::BAD_REQUEST, "runtime-package-not-public-chirho")
        };
    super::public_error_chirho::public_error_response_chirho(
        "runtime-package-chirho",
        super::public_error_chirho::classify_non_dag_chirho(
            &error_chirho,
            status_chirho,
            identity_chirho,
        ),
        &axum::http::HeaderMap::new(),
        None,
    )
}
