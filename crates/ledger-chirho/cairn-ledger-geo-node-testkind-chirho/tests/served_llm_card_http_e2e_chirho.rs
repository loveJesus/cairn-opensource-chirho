// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! a2b — the served-LLM card completes over REAL loopback HTTP, settling the SAME certified money
//! ladder a2 proved by direct call. This is the labeled intermediate on the user-pays model:
//! browser form -> app-route POST -> DAG -> blessed `llm_chirho` paid effect -> completion, with the
//! dev-only served-LLM composition injected into the serve runtime (StubLlmProvider, fixed price 7,
//! loopback listener only, no host, no activation).
//!
//! Setup mirrors a2 (`served_llm_dev_composition_e2e_chirho.rs`): a1's durable test-kind root funds
//! the payer, and the resident handle is the elected write authority for every app-control-plane and
//! ledger write. a2b then DEPLOYS the card app on that root (a pure `render_form` root DAG for GET
//! and a `build -> llm -> render_card` route DAG for POST), INJECTS the composition into the serve
//! runtime, and drives it over loopback HTTP.
//!
//! The full flow (Phases 3 + 4): the POST is a real `application/x-www-form-urlencoded` browser
//! submission. A pure build node turns the form into the `llm-request-v1-chirho` the effect consumes,
//! reading only the description; the issued caller idempotency key rides in the body (a browser
//! form cannot set a header), is extracted by the serve dispatch for idempotency, and is dropped from
//! the prompt by the build node. The paid effect drafts the page, a pure render-card node renders the
//! sealed completion into an HTML card with a "draft again" retry form, and the serve engine fills each
//! empty caller-key placeholder a render node emits with its own fresh key after the render (the
//! browser caller-key carrier), with `Cache-Control: private, no-store`.

use cairn_chirho::app_chirho::{
    deploy_app_route_with_head_transition_authority_chirho,
    deploy_app_with_head_transition_authority_chirho, set_app_input_policy_chirho,
    set_app_response_policy_chirho, set_app_route_response_policy_chirho, AppInputModeChirho,
};
use cairn_chirho::dag_private_value_chirho::{
    load_private_dag_value_bytes_chirho, verified_private_dag_value_hashes_chirho,
};
use cairn_chirho::durable_chirho::cas_lifecycle_chirho::migrate_cas_lifecycle_offline_chirho;
use cairn_chirho::effect_chirho::llm_served_chirho::AppPriceBookUserPaysLlmPolicyChirho;
use cairn_chirho::effect_pricing_chirho::set_price_book_with_head_transition_authority_chirho;
use cairn_chirho::identity_chirho::{
    login_identity_with_credential_chirho, register_identity_chirho,
    register_identity_with_credential_chirho, PrincipalKindChirho,
};
use cairn_chirho::model_chirho::{
    CapabilityChirho, DagChirho, EdgeChirho, HashChirho, NodeDefChirho, PortChirho,
};
use cairn_chirho::{cas_chirho, store_chirho};
use cairn_config_chirho::config_chirho::load_config_chirho;
use cairn_ledger_geo_node_testkind_chirho::testkind_normal_settlement_resident_opener_chirho;
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho, require_test_kind_marked_host_config_chirho,
    HostLedgerSignersChirho,
};
use cairn_ledger_model_chirho::ids_chirho::AssetKindIdChirho;
use cairn_llm_served_effect_chirho::{
    LlmProviderChirho, LlmProviderOutcomeChirho, LlmRefusalCodeChirho, LlmRequestChirho,
    LlmResponseChirho, StubLlmProviderChirho,
};
use cairn_serve_runtime_chirho::{
    open_shared_llm_served_composition_with_resident_journal_chirho,
    serve_with_dev_llm_served_composition_until_chirho, LedgerHostProjectionReadPortChirho,
    OpenSharedLlmServedCompositionParamsChirho, ServedLlmCardSurfaceChirho,
    SERVED_LLM_DEV_ROOT_MISMATCH_REFUSAL_CHIRHO,
};
use cairn_served_llm_dev_bootstrap_chirho::{
    run_served_llm_dev_bootstrap_chirho, ServedLlmDevBootstrapRequestChirho,
};
use cairn_undo_plan_chirho::canonical_chirho::contract_set_digest_chirho;
use cairn_undo_plan_chirho::contract_chirho::{
    canonical_authoring_reversion_contract_set_chirho, LLM_SERVED_EFFECT_SUBTYPE_CHIRHO,
};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

// The fail-closed CAS plaintext scanner is SHARED test support (Finding 1): a2b reuses a2's proven
// Result-based walk (which propagates read_dir/entry/file-type/read errors as `Err` rather than
// `.flatten()`-skipping them) instead of hand-rolling a fresh walk. It lives in a tests/ SUBDIRECTORY,
// so cargo does not compile it as its own test binary; its armed self-test proves the walk fails
// CLOSED on both a broken symlink and an unreadable directory.
#[path = "served_llm_scan_support_chirho/mod.rs"]
mod served_llm_scan_support_chirho;
use served_llm_scan_support_chirho::{contains_subslice_chirho, scan_root_for_needle_chirho};

// The guest app's app/route/field constants, mirrored inline. `tree-llm-card-chirho` declares its
// own `[workspace]`, so it cannot be a cargo dependency of this workspace member; the test builds
// its `render_form` wasm via a cargo subprocess instead. These MUST stay identical to
// `tree_llm_card_chirho::implementations_chirho::render_form_chirho::{APP_NAME_CHIRHO,
// DRAFT_ROUTE_CHIRHO, DESCRIPTION_FIELD_NAME_CHIRHO}` so the rendered form's action matches the
// deployed route.
const APP_NAME_CHIRHO: &str = "served-llm-card-e2e-chirho";
const DRAFT_ROUTE_CHIRHO: &str = "draft-chirho";
const DESCRIPTION_FIELD_NAME_CHIRHO: &str = "description_chirho";
/// A SECOND deployed app with the SAME paid-route name. It exists so a POST to its draft route reaches
/// the served-scope app-name check (returning to the unchanged dispatch), rather than dying early at
/// request-context resolution the way a never-deployed app does.
const OTHER_APP_NAME_CHIRHO: &str = "other-served-app-e2e-chirho";

const AMOUNT_CHIRHO: u64 = 137;
const LLM_PRICE_CHIRHO: u64 = 7;
const BILLING_KIND_CHIRHO: &str = "llm-credit-chirho";
const SETTLEMENT_OWNER_CHIRHO: &str = "dev-settlement-owner-chirho";
const USER_CREDENTIAL_CHIRHO: &str = "a2b-user-session-secret-chirho";
/// The cookie name the serve session helper reads (`AUTH_SESSION_COOKIE_CHIRHO` is `pub(super)`, so
/// its value is mirrored here; the serve-crate tests use the same literal shape).
const SESSION_COOKIE_NAME_CHIRHO: &str = "cairn_session_chirho";
/// The hidden form field the issued caller idempotency key rides in (a browser form cannot set a
/// request header, so the served card carries the key in the url-encoded body). Mirror of the guest
/// build node's and the serve dispatch's `IDEMPOTENCY_KEY_FIELD_NAME_CHIRHO`.
const IDEMPOTENCY_KEY_FIELD_NAME_CHIRHO: &str = "idempotency_key_chirho";
/// The exact empty placeholder each render node emits once per POST form (mirror of the serve crate's
/// and the guest's `FORM_CALLER_KEY_PLACEHOLDER_CHIRHO`). The engine fills every one with a fresh key
/// after the render, so a served page must NEVER still carry it empty.
const FORM_CALLER_KEY_PLACEHOLDER_CHIRHO: &str =
    "<input type=\"hidden\" name=\"idempotency_key_chirho\" value=\"\">";
/// The served-app private-input sentinel subject (mirror of the serve crate's `pub(super)`
/// `REQUEST_USER_PRIVATE_INPUT_SUBJECT_CHIRHO`): a `PrivateBlobRefChirho` route policy with THIS
/// subject makes the serve path seal the request body under the authenticated request user. A
/// literal principal instead falls through to a public body, so this exact value is load-bearing.
const REQUEST_USER_PRIVATE_INPUT_SUBJECT_CHIRHO: &str = "request-user-chirho";

/// Serializes the two tests that toggle the process-global `CAIRN_DEV_LLM_SERVED_CHIRHO` env fence,
/// so a parallel test never observes it mid-toggle. Poison-tolerant: a panicking test still frees it.
static A2B_SERVE_ENV_LOCK_CHIRHO: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A provider that blocks inside `complete_chirho` (holding the composition lock through the draft)
/// until it is released, so a test can hold the single composition and fire a concurrent request.
/// It signals when it has entered (lock held) and then delegates to the real stub for a valid
/// completion. No network, no spend.
struct PausableStubProviderChirho {
    entered_tx_chirho: std::sync::mpsc::SyncSender<()>,
    release_rx_chirho: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl LlmProviderChirho for PausableStubProviderChirho {
    fn complete_chirho(&self, request_chirho: &LlmRequestChirho) -> LlmProviderOutcomeChirho {
        let _ = self.entered_tx_chirho.send(());
        if let Ok(release_rx_chirho) = self.release_rx_chirho.lock() {
            let _ = release_rx_chirho.recv();
        }
        StubLlmProviderChirho.complete_chirho(request_chirho)
    }
}

/// A provider that counts how many times it is invoked, then delegates to the real stub (or returns a
/// typed refusal on the marker brief, Finding 4). Its count is provider-CALL evidence, distinct from
/// the balance: "no additional net settled debit" and "no additional provider call" are different
/// claims, and NEITHER proves no earlier request/intent persistence or effect-machinery entry. The
/// witness used below is that the counter is UNCHANGED across the negatives (they never reached the
/// provider) -- not a fixed total, since the completing/replay/refusal POSTs each call the provider.
struct CountingStubProviderChirho {
    invocations_chirho: Arc<AtomicUsize>,
}

/// A brief carrying this marker makes the counting provider return a TYPED provider refusal (for the
/// Finding-4 refusal-render arm). A provider refusal maps to `DefiniteNoEffect` and releases the whole
/// Hold, so it settles NO charge.
const PROVIDER_REFUSAL_MARKER_CHIRHO: &str = "REFUSE-ME-CHIRHO";

impl LlmProviderChirho for CountingStubProviderChirho {
    fn complete_chirho(&self, request_chirho: &LlmRequestChirho) -> LlmProviderOutcomeChirho {
        self.invocations_chirho.fetch_add(1, Ordering::SeqCst);
        // Finding 4: a marked brief returns a typed provider refusal (the drafting service is
        // unavailable), so the served flow renders an honest refusal card rather than a fake success.
        if request_chirho
            .user_chirho
            .contains(PROVIDER_REFUSAL_MARKER_CHIRHO)
        {
            return LlmProviderOutcomeChirho::RefusedChirho(
                LlmRefusalCodeChirho::ProviderUnavailableChirho,
            );
        }
        StubLlmProviderChirho.complete_chirho(request_chirho)
    }
}

/// Arm 6 (fail-closed CAS plaintext scan): reuse the SHARED a2 Result-based walk over the PUBLIC
/// content-addressed store (`objects-chirho/`). Every enumerated path must be READ successfully, so a
/// broken symlink or an unreadable directory REFUSES the scan (`Err` -> `.expect` panic = test FAIL)
/// rather than being silently skipped (the old `.flatten()` + `is_file()` defect, Finding 1). Private
/// blobs store only XChaCha20 ciphertext, so a correctly-sealed prompt/completion leaves no plaintext
/// at rest; the needle must appear in ZERO objects. Fail-closed on coverage too: objects-chirho/ must
/// exist and at least one object must be read (never green-by-emptiness). Returns the objects read.
fn assert_no_plaintext_needle_in_public_cas_chirho(
    root_chirho: &std::path::Path,
    needle_chirho: &str,
) -> u64 {
    let objects_dir_chirho = root_chirho.join("objects-chirho");
    assert!(
        objects_dir_chirho.is_dir(),
        "Arm 6: the public CAS objects-chirho/ directory must exist to scan"
    );
    let (found_chirho, read_count_chirho) =
        scan_root_for_needle_chirho(&objects_dir_chirho, needle_chirho.as_bytes()).expect(
            "Arm 6: every CAS object must be readable (fail-closed; an unreadable surface REFUSES \
             the scan rather than skipping it)",
        );
    assert!(
        !found_chirho,
        "Arm 6 BLOCKER: plaintext needle found at rest in public CAS"
    );
    assert!(
        read_count_chirho > 0,
        "Arm 6: the scan must read at least one CAS object (never green-by-emptiness)"
    );
    read_count_chirho
}

/// Count the public CAS objects currently at rest (via the shared fail-closed walk with an ABSENT
/// needle), for the Finding-6g before/after persistence witness on a rejected negative.
fn count_public_cas_objects_chirho(root_chirho: &std::path::Path) -> u64 {
    let objects_dir_chirho = root_chirho.join("objects-chirho");
    let (_found_chirho, read_count_chirho) = scan_root_for_needle_chirho(
        &objects_dir_chirho,
        b"cairn-absent-persistence-probe-chirho",
    )
    .expect("the CAS object census must read every object (fail-closed)");
    read_count_chirho
}

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let nanos_chirho = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cairn-served-llm-card-http-{label_chirho}-{}-{nanos_chirho}-{counter_chirho}-chirho",
        std::process::id()
    ))
}

/// The `effect_contract_set` the paid-effect node carries, from the SAME canonical descriptor-v2
/// contract set the runtime verifies against (mirror of a2's helper).
fn effect_contract_set_chirho() -> HashChirho {
    contract_set_digest_chirho(&canonical_authoring_reversion_contract_set_chirho())
        .expect("canonical descriptor-v2 contract set")
}

/// Compile a guest example to wasm32 with an EXPLICIT `--target-dir` (so a custom `CARGO_TARGET_DIR`
/// on the outer test run cannot relocate the artifact) and read the bytes. The guest crate is a
/// standalone workspace, so it is built by path.
fn build_and_read_guest_wasm_chirho(example_chirho: &str) -> Vec<u8> {
    let manifest_dir_chirho = env!("CARGO_MANIFEST_DIR");
    let guest_manifest_chirho =
        format!("{manifest_dir_chirho}/../../../examples-chirho/tree-llm-card-chirho/Cargo.toml");
    let guest_target_chirho = format!(
        "{manifest_dir_chirho}/../../../examples-chirho/tree-llm-card-chirho/target-guest-chirho"
    );
    let status_chirho = std::process::Command::new(env!("CARGO"))
        .args([
            "build",
            "--manifest-path",
            &guest_manifest_chirho,
            "--example",
            example_chirho,
            "--target",
            "wasm32-unknown-unknown",
            "--target-dir",
            &guest_target_chirho,
        ])
        .env_remove("CARGO_TARGET_DIR")
        .status()
        .unwrap_or_else(|_| panic!("run cargo build for the {example_chirho} guest wasm"));
    assert!(
        status_chirho.success(),
        "the {example_chirho} guest wasm build must succeed"
    );
    let wasm_path_chirho = format!(
        "{guest_target_chirho}/wasm32-unknown-unknown/debug/examples/{example_chirho}.wasm"
    );
    std::fs::read(&wasm_path_chirho)
        .unwrap_or_else(|_| panic!("read the built {example_chirho} guest wasm"))
}

/// The `application/x-www-form-urlencoded` body a browser submits from the draft form: the business
/// description plus the issued caller idempotency key hidden field. Values here are URL-safe
/// (ASCII, no reserved chars), so a plain join is faithful. The build node wraps the description as
/// the labelled business name the stub drafts from, so ONE needle rides both the prompt and the
/// completion.
fn draft_form_body_chirho(description_chirho: &str, caller_key_chirho: &str) -> Vec<u8> {
    format!(
        "{DESCRIPTION_FIELD_NAME_CHIRHO}={description_chirho}&\
         {IDEMPOTENCY_KEY_FIELD_NAME_CHIRHO}={caller_key_chirho}"
    )
    .into_bytes()
}

/// Extract the issued caller key from a rendered form's hidden field
/// (`name="idempotency_key_chirho" value="<KEY>"`). Panics if the field is absent or unquoted.
fn caller_key_from_rendered_form_chirho(html_chirho: &[u8]) -> String {
    let text_chirho = String::from_utf8_lossy(html_chirho);
    let marker_chirho = format!("name=\"{IDEMPOTENCY_KEY_FIELD_NAME_CHIRHO}\" value=\"");
    let start_chirho = text_chirho
        .find(&marker_chirho)
        .map(|index_chirho| index_chirho + marker_chirho.len())
        .expect("a rendered form must carry the caller-key field");
    let rest_chirho = &text_chirho[start_chirho..];
    let end_chirho = rest_chirho
        .find('"')
        .expect("the caller-key value must be quoted");
    rest_chirho[..end_chirho].to_string()
}

/// The key the engine issued into a served page: no empty placeholder is left, and the key is 43
/// base64url characters (32 random bytes), as the carrier issues it.
fn issued_caller_key_chirho(page_chirho: &[u8], what_chirho: &str) -> String {
    assert!(
        !contains_subslice_chirho(page_chirho, FORM_CALLER_KEY_PLACEHOLDER_CHIRHO.as_bytes()),
        "{what_chirho}: every placeholder must be filled before the page leaves"
    );
    let key_chirho = caller_key_from_rendered_form_chirho(page_chirho);
    assert!(
        key_chirho.len() == 43
            && key_chirho.bytes().all(|byte_chirho| {
                byte_chirho.is_ascii_alphanumeric() || byte_chirho == b'-' || byte_chirho == b'_'
            }),
        "{what_chirho}: the issued key must be 43 base64url characters, not {} bytes",
        key_chirho.len()
    );
    key_chirho
}

fn unused_loopback_port_chirho() -> u16 {
    let listener_chirho =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral loopback port");
    let port_chirho = listener_chirho.local_addr().unwrap().port();
    drop(listener_chirho);
    port_chirho
}

fn wait_for_serve_health_chirho(base_chirho: &str) {
    for _ in 0..200 {
        let ok_chirho = ureq::get(&format!("{base_chirho}/healthz-chirho"))
            .timeout(Duration::from_millis(500))
            .call()
            .map(|response_chirho| response_chirho.status() == 200)
            .unwrap_or(false);
        if ok_chirho {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("served runtime did not become healthy on {base_chirho}");
}

/// GET with the session cookie; returns (status, body-bytes).
fn http_get_with_cookie_chirho(
    base_chirho: &str,
    path_chirho: &str,
    cookie_chirho: &str,
) -> (u16, Vec<u8>) {
    let response_chirho = ureq::get(&format!("{base_chirho}{path_chirho}"))
        .set("Cookie", cookie_chirho)
        .timeout(Duration::from_secs(20))
        .call();
    read_ureq_response_chirho(response_chirho)
}

/// GET and return the response's `Cache-Control` header value (for asserting the served card is
/// `private, no-store` so an issued key is never cached or replayed).
fn http_get_cache_control_chirho(
    base_chirho: &str,
    path_chirho: &str,
    cookie_chirho: &str,
) -> Option<String> {
    ureq::get(&format!("{base_chirho}{path_chirho}"))
        .set("Cookie", cookie_chirho)
        .timeout(Duration::from_secs(20))
        .call()
        .ok()
        .and_then(|response_chirho| response_chirho.header("Cache-Control").map(str::to_string))
}

/// POST an `application/x-www-form-urlencoded` body with the session cookie (a browser form
/// submission, as htmx-lite sends it); returns (status, body-bytes). The caller idempotency key rides
/// IN the body, so there is no key header — the negatives vary the body itself.
fn http_post_form_chirho(
    base_chirho: &str,
    path_chirho: &str,
    cookie_chirho: &str,
    form_body_chirho: &[u8],
) -> (u16, Vec<u8>) {
    let response_chirho = ureq::post(&format!("{base_chirho}{path_chirho}"))
        .set("Cookie", cookie_chirho)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .timeout(Duration::from_secs(20))
        .send_bytes(form_body_chirho);
    read_ureq_response_chirho(response_chirho)
}

/// POST a form WITHOUT following redirects, optionally with the caller-key header a script sends;
/// returns (status, Location, body-bytes). A refused browser form answers 303, so a client that
/// followed it would only see the page it lands on.
fn http_post_form_raw_chirho(
    base_chirho: &str,
    path_chirho: &str,
    cookie_chirho: &str,
    form_body_chirho: &[u8],
    caller_key_header_chirho: Option<&str>,
) -> (u16, Option<String>, Vec<u8>) {
    let agent_chirho = ureq::AgentBuilder::new().redirects(0).build();
    let mut request_chirho = agent_chirho
        .post(&format!("{base_chirho}{path_chirho}"))
        .set("Cookie", cookie_chirho)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .timeout(Duration::from_secs(20));
    if let Some(caller_key_chirho) = caller_key_header_chirho {
        request_chirho = request_chirho.set("cairn-idempotency-key-chirho", caller_key_chirho);
    }
    match request_chirho.send_bytes(form_body_chirho) {
        Ok(response_chirho) | Err(ureq::Error::Status(_, response_chirho)) => {
            let status_chirho = response_chirho.status();
            let location_chirho = response_chirho.header("Location").map(str::to_string);
            let mut body_chirho = Vec::new();
            response_chirho
                .into_reader()
                .read_to_end(&mut body_chirho)
                .expect("read the response body");
            (status_chirho, location_chirho, body_chirho)
        }
        Err(error_chirho) => panic!("the POST did not reach the server: {error_chirho}"),
    }
}

fn read_ureq_response_chirho(
    response_chirho: Result<ureq::Response, ureq::Error>,
) -> (u16, Vec<u8>) {
    match response_chirho {
        Ok(response_chirho) => {
            let status_chirho = response_chirho.status();
            let mut body_chirho = Vec::new();
            response_chirho
                .into_reader()
                .read_to_end(&mut body_chirho)
                .expect("read response body");
            (status_chirho, body_chirho)
        }
        Err(ureq::Error::Status(code_chirho, response_chirho)) => {
            let mut body_chirho = Vec::new();
            let _ = response_chirho.into_reader().read_to_end(&mut body_chirho);
            (code_chirho, body_chirho)
        }
        Err(other_chirho) => panic!("loopback HTTP transport error: {other_chirho}"),
    }
}

/// PROOF Arm 1: the served-LLM card completes over REAL loopback HTTP and settles the a2 money
/// ladder. GET the app root -> 200 form present; POST a valid brief to the draft route -> 200
/// completion carrying the drafted name; then stop the server (releasing the ledger lock) and assert
/// the ladder via `read_substrate_balances_chirho` (payer debited 7, settlement credited 7, supply
/// conserved, no Hold), matching a2.
#[test]
fn served_llm_card_completes_over_loopback_http_conserved_chirho() {
    let _env_guard_chirho = A2B_SERVE_ENV_LOCK_CHIRHO
        .lock()
        .unwrap_or_else(|poison_chirho| poison_chirho.into_inner());
    let root_chirho = temp_root_chirho("arm1");
    std::fs::create_dir_all(&root_chirho).unwrap();

    // The app authority (deploy owner) and the payer (a session-capable user, registered with a
    // credential so it can log in and carry a browser session over HTTP).
    let owner_chirho = register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
        .expect("register the app owner identity")
        .principal_chirho;
    let user_registration_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        USER_CREDENTIAL_CHIRHO,
    )
    .expect("register the payer user with a credential");
    let user_chirho = user_registration_chirho.principal_chirho;

    // Fund the payer via a1 on THIS root (mint 137, kind policy with the settlement owner, test-kind
    // config), alongside the identity records already written above.
    let report_chirho = run_served_llm_dev_bootstrap_chirho(ServedLlmDevBootstrapRequestChirho {
        root_chirho: &root_chirho,
        payer_principal_chirho: &user_chirho,
        owner_principal_chirho: SETTLEMENT_OWNER_CHIRHO,
        amount_chirho: AMOUNT_CHIRHO,
        billing_kind_chirho: BILLING_KIND_CHIRHO,
    })
    .expect("a1 dev bootstrap must fund the payer");
    let canonical_root_chirho = root_chirho.canonicalize().expect("canonical root");
    let config_path_chirho = canonical_root_chirho.join(&report_chirho.config_file_chirho);
    let ledger_host_chirho = load_config_chirho(&config_path_chirho)
        .expect("load a1 config")
        .ledger_host_chirho
        .expect("a1 config carries a ledger host block");

    // The ELECTED app-control-plane deploy path requires an initialized CAS lifecycle; the root is
    // quiescent here (a1 finished; no resident actor open yet), so the offline migration is correct.
    migrate_cas_lifecycle_offline_chirho(&canonical_root_chirho)
        .expect("initialize the CAS lifecycle on a1's populated dev root");

    // Log the user in and build the browser session cookie the serve path authenticates the payer
    // from (so the served card debits exactly the account a1 funded).
    let login_chirho = login_identity_with_credential_chirho(
        &canonical_root_chirho,
        &user_chirho,
        USER_CREDENTIAL_CHIRHO,
    )
    .expect("log the payer user in");
    let session_cookie_chirho = format!(
        "{SESSION_COOKIE_NAME_CHIRHO}={}:{}",
        user_chirho, login_chirho.token_chirho
    );

    // Build the two DAGs (CAS-only, authority-free): the pure render_form root DAG and the single
    // llm_chirho paid-effect route DAG.
    let bytes_schema_chirho = cas_chirho::add_chirho(&canonical_root_chirho, b"bytes").unwrap();
    let render_wasm_chirho = build_and_read_guest_wasm_chirho("render_form_guest_chirho");
    let render_impl_chirho =
        cas_chirho::add_chirho(&canonical_root_chirho, &render_wasm_chirho).unwrap();
    let render_node_chirho = NodeDefChirho {
        name_chirho: "render-form-node-chirho".to_owned(),
        impl_wasm_chirho: render_impl_chirho,
        entry_chirho: "render_form_chirho".to_owned(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        capabilities_chirho: Vec::new(),
        fuel_limit_chirho: 200_000_000,
        ..NodeDefChirho::default()
    };
    let render_node_hash_chirho =
        store_chirho::put_object_chirho(&canonical_root_chirho, &render_node_chirho).unwrap();
    let root_dag_hash_chirho = store_chirho::put_object_chirho(
        &canonical_root_chirho,
        &DagChirho {
            nodes_chirho: vec![render_node_hash_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();

    let llm_node_chirho = NodeDefChirho {
        name_chirho: "draft-llm-node-chirho".to_owned(),
        impl_wasm_chirho: cas_chirho::add_chirho(&canonical_root_chirho, b"draft-llm-node-chirho")
            .unwrap(),
        entry_chirho: "draft_llm_chirho".to_owned(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        capabilities_chirho: vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: LLM_SERVED_EFFECT_SUBTYPE_CHIRHO.to_owned(),
            caller_chirho: "served-llm-card-http-runtime-chirho".to_owned(),
        }],
        effect_contract_set_chirho: Some(effect_contract_set_chirho()),
        fuel_limit_chirho: 0,
        ..NodeDefChirho::default()
    };
    let llm_node_hash_chirho =
        store_chirho::put_object_chirho(&canonical_root_chirho, &llm_node_chirho).unwrap();

    // Phase 3: a PURE build node turns the url-encoded form submission into the llm-request-v1 the
    // paid effect consumes -- reading ONLY the description (the caller key is dropped, never in the
    // prompt). Its output inherits the sealed form body's private subject, so the intermediate request
    // is sealed too (never public CAS). The route DAG runs build -> llm over one edge.
    let build_wasm_chirho = build_and_read_guest_wasm_chirho("build_llm_request_guest_chirho");
    let build_node_chirho = NodeDefChirho {
        name_chirho: "build-llm-request-node-chirho".to_owned(),
        impl_wasm_chirho: cas_chirho::add_chirho(&canonical_root_chirho, &build_wasm_chirho)
            .unwrap(),
        entry_chirho: "build_llm_request_chirho".to_owned(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        capabilities_chirho: Vec::new(),
        fuel_limit_chirho: 200_000_000,
        ..NodeDefChirho::default()
    };
    let build_node_hash_chirho =
        store_chirho::put_object_chirho(&canonical_root_chirho, &build_node_chirho).unwrap();

    // Phase 4: a PURE render-card node turns the sealed llm-response into the drafted card HTML with a
    // "draft again" retry form (carrying the empty caller-key placeholder the engine fills). It inherits the sealed
    // viewer subject, so the card is sealed at rest. The route DAG runs build -> llm -> render_card.
    let render_card_wasm_chirho = build_and_read_guest_wasm_chirho("render_card_guest_chirho");
    let render_card_node_chirho = NodeDefChirho {
        name_chirho: "render-card-node-chirho".to_owned(),
        impl_wasm_chirho: cas_chirho::add_chirho(&canonical_root_chirho, &render_card_wasm_chirho)
            .unwrap(),
        entry_chirho: "render_card_chirho".to_owned(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        capabilities_chirho: Vec::new(),
        fuel_limit_chirho: 200_000_000,
        ..NodeDefChirho::default()
    };
    let render_card_node_hash_chirho =
        store_chirho::put_object_chirho(&canonical_root_chirho, &render_card_node_chirho).unwrap();
    let route_dag_hash_chirho = store_chirho::put_object_chirho(
        &canonical_root_chirho,
        &DagChirho {
            nodes_chirho: vec![
                build_node_hash_chirho.clone(),
                llm_node_hash_chirho.clone(),
                render_card_node_hash_chirho.clone(),
            ],
            edges_chirho: vec![
                EdgeChirho {
                    from_node_chirho: build_node_hash_chirho,
                    from_port_chirho: "out".to_owned(),
                    to_node_chirho: llm_node_hash_chirho.clone(),
                    to_port_chirho: "in".to_owned(),
                    privacy_chirho: None,
                },
                EdgeChirho {
                    from_node_chirho: llm_node_hash_chirho,
                    from_port_chirho: "out".to_owned(),
                    to_node_chirho: render_card_node_hash_chirho,
                    to_port_chirho: "in".to_owned(),
                    privacy_chirho: None,
                },
            ],
        },
    )
    .unwrap();

    // Load the runtime signers (custody-derived from the root's own secret store).
    let signer_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&ledger_host_chirho.signer_secrets_chirho)
            .expect("derive signer refs from config");
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&canonical_root_chirho, &signer_refs_chirho)
            .expect("load the runtime signers");

    let pii_needle_chirho = "Zzyzx-A2B-Served-Card-Needle-Chirho";

    // Open the durable root through the DEV-ONLY test-kind resident door. This handle IS the elected
    // write authority: deploy, route, and price book all go through its head-transition authority.
    let handle_chirho = testkind_normal_settlement_resident_opener_chirho(
        &canonical_root_chirho,
        &config_path_chirho,
        &ledger_host_chirho,
    )
    .expect("open a1's durable test-kind root through the dev-only door");

    // Move the app/route/price-book refs through the elected authority (authority BORROWED per call).
    deploy_app_with_head_transition_authority_chirho(
        &canonical_root_chirho,
        APP_NAME_CHIRHO,
        root_dag_hash_chirho.clone(),
        &owner_chirho,
        handle_chirho.head_transition_authority_chirho(),
    )
    .expect("deploy the served-LLM card app (render_form root DAG)");
    deploy_app_route_with_head_transition_authority_chirho(
        &canonical_root_chirho,
        APP_NAME_CHIRHO,
        DRAFT_ROUTE_CHIRHO,
        route_dag_hash_chirho.clone(),
        &owner_chirho,
        handle_chirho.head_transition_authority_chirho(),
    )
    .expect("deploy the draft POST route (llm_chirho paid-effect DAG)");
    // The render root is a pure GET form render with no request-body PII, so its input surface is
    // Plain. M140 removed implicit Plain defaults, so even this surface needs an explicit signed
    // policy before the runtime will handle its request. Authority-free (signed record).
    set_app_input_policy_chirho(
        &canonical_root_chirho,
        APP_NAME_CHIRHO,
        None,
        &owner_chirho,
        AppInputModeChirho::PlainChirho,
    )
    .expect("set the render root's plain input policy");
    // The prompt carries the drafted business name (PII), so the draft route seals the request body
    // as a viewer-subject private blob before it reaches the DAG/CAS. Authority-free (signed record).
    set_app_input_policy_chirho(
        &canonical_root_chirho,
        APP_NAME_CHIRHO,
        Some(DRAFT_ROUTE_CHIRHO),
        &owner_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: REQUEST_USER_PRIVATE_INPUT_SUBJECT_CHIRHO.to_owned(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .expect("seal the draft route's request body as a request-user private blob");
    // Both surfaces answer pages, so they declare text/html, as a real app does: undeclared, they would
    // leave as application/octet-stream, which a browser with nosniff will not render, and the engine
    // never issues caller keys into it. Authority-free (signed records).
    set_app_response_policy_chirho(
        &canonical_root_chirho,
        APP_NAME_CHIRHO,
        &owner_chirho,
        "text/html; charset=utf-8",
    )
    .expect("declare the render root's pages as HTML");
    set_app_route_response_policy_chirho(
        &canonical_root_chirho,
        APP_NAME_CHIRHO,
        DRAFT_ROUTE_CHIRHO,
        &owner_chirho,
        "text/html; charset=utf-8",
    )
    .expect("declare the draft route's card as HTML");
    let _price_book_chirho = set_price_book_with_head_transition_authority_chirho(
        &canonical_root_chirho,
        APP_NAME_CHIRHO,
        &owner_chirho,
        None,
        BTreeMap::from([(
            LLM_SERVED_EFFECT_SUBTYPE_CHIRHO.to_owned(),
            LLM_PRICE_CHIRHO as i64,
        )]),
        0,
        handle_chirho.head_transition_authority_chirho(),
    )
    .expect("set the served-LLM price book");

    // Deploy a SECOND app with the SAME "draft-chirho" route name and a valid context (owner, route,
    // input policy, price book), so a POST to it reaches the served-scope app-name check instead of
    // failing early at request-context resolution. The served dispatch must NOT admit it (name-scoped).
    deploy_app_with_head_transition_authority_chirho(
        &canonical_root_chirho,
        OTHER_APP_NAME_CHIRHO,
        root_dag_hash_chirho,
        &owner_chirho,
        handle_chirho.head_transition_authority_chirho(),
    )
    .expect("deploy the second (non-served) app");
    deploy_app_route_with_head_transition_authority_chirho(
        &canonical_root_chirho,
        OTHER_APP_NAME_CHIRHO,
        DRAFT_ROUTE_CHIRHO,
        route_dag_hash_chirho,
        &owner_chirho,
        handle_chirho.head_transition_authority_chirho(),
    )
    .expect("deploy the second app's same-named draft route");
    set_app_input_policy_chirho(
        &canonical_root_chirho,
        OTHER_APP_NAME_CHIRHO,
        None,
        &owner_chirho,
        AppInputModeChirho::PlainChirho,
    )
    .expect("set the second app's render root input policy");
    set_app_input_policy_chirho(
        &canonical_root_chirho,
        OTHER_APP_NAME_CHIRHO,
        Some(DRAFT_ROUTE_CHIRHO),
        &owner_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: REQUEST_USER_PRIVATE_INPUT_SUBJECT_CHIRHO.to_owned(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .expect("set the second app's draft route input policy");
    let _other_price_book_chirho = set_price_book_with_head_transition_authority_chirho(
        &canonical_root_chirho,
        OTHER_APP_NAME_CHIRHO,
        &owner_chirho,
        None,
        BTreeMap::from([(
            LLM_SERVED_EFFECT_SUBTYPE_CHIRHO.to_owned(),
            LLM_PRICE_CHIRHO as i64,
        )]),
        0,
        handle_chirho.head_transition_authority_chirho(),
    )
    .expect("set the second app's price book");

    // Build the shared composition over the fenced resident handle (moves the handle) and inject it
    // into the dev serve entry. verify_runtime_binding_chirho is rechecked FIRST inside the opener.
    // The counting provider is the INDEPENDENT authority witness: the paid effect invokes it exactly
    // once (the happy POST), so every negative below is proven to reject BEFORE the effect.
    let provider_invocations_chirho = Arc::new(AtomicUsize::new(0));
    let composition_chirho = open_shared_llm_served_composition_with_resident_journal_chirho(
        OpenSharedLlmServedCompositionParamsChirho {
            root_chirho: &canonical_root_chirho,
            handle_chirho,
            signers_chirho,
            provider_chirho: Box::new(CountingStubProviderChirho {
                invocations_chirho: provider_invocations_chirho.clone(),
            }),
            policy_chirho: Box::new(AppPriceBookUserPaysLlmPolicyChirho),
            billing_kind_chirho: AssetKindIdChirho(BILLING_KIND_CHIRHO.to_owned()),
            ledger_config_chirho: &ledger_host_chirho,
            served_surface_chirho: ServedLlmCardSurfaceChirho::new_chirho(
                APP_NAME_CHIRHO,
                DRAFT_ROUTE_CHIRHO,
            ),
        },
    )
    .expect("compose the served-LLM runtime over the fenced resident handle");

    // Serve on a background tokio runtime with a graceful-shutdown stop signal (loopback only).
    let port_chirho = unused_loopback_port_chirho();
    let base_chirho = format!("http://127.0.0.1:{port_chirho}");
    std::env::set_var("CAIRN_DEV_LLM_SERVED_CHIRHO", "1");
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let server_root_chirho = canonical_root_chirho.clone();
    let server_stop_chirho = stop_chirho.clone();
    let server_handle_chirho = runtime_chirho.spawn(async move {
        serve_with_dev_llm_served_composition_until_chirho(
            &server_root_chirho,
            port_chirho,
            8,
            String::new(),
            String::new(),
            composition_chirho,
            Some(server_stop_chirho),
        )
        .await
    });

    wait_for_serve_health_chirho(&base_chirho);

    // GET the app root -> 200 form present (the JS-free describe-your-business form), carrying a
    // freshly ISSUED caller key (no empty placeholder left).
    let (form_status_chirho, form_body_chirho) = http_get_with_cookie_chirho(
        &base_chirho,
        &format!("/app-chirho/{APP_NAME_CHIRHO}/"),
        &session_cookie_chirho,
    );
    assert_eq!(form_status_chirho, 200, "GET the card form must be 200");
    assert!(
        contains_subslice_chirho(&form_body_chirho, b"<textarea")
            && contains_subslice_chirho(
                &form_body_chirho,
                DESCRIPTION_FIELD_NAME_CHIRHO.as_bytes()
            ),
        "the GET response must be the describe-your-business form"
    );
    // ARM 2: the engine fills the form's empty placeholder after the render, so the GET form
    // carries a valid issued key and no empty placeholder.
    let get_key_1_chirho = issued_caller_key_chirho(&form_body_chirho, "the GET form");
    // A second cached render must carry a DISTINCT key (render node cached; the engine issues fresh).
    let (_second_status_chirho, form_body_2_chirho) = http_get_with_cookie_chirho(
        &base_chirho,
        &format!("/app-chirho/{APP_NAME_CHIRHO}/"),
        &session_cookie_chirho,
    );
    let get_key_2_chirho = caller_key_from_rendered_form_chirho(&form_body_2_chirho);
    assert_ne!(
        get_key_1_chirho, get_key_2_chirho,
        "ARM 2: two cached GET renders must carry DISTINCT issued keys"
    );
    // Phase 4: the served-card render is Cache-Control: private, no-store (an issued key
    // must never be cached and replayed).
    assert_eq!(
        http_get_cache_control_chirho(
            &base_chirho,
            &format!("/app-chirho/{APP_NAME_CHIRHO}/"),
            &session_cookie_chirho,
        )
        .as_deref(),
        Some("private, no-store"),
        "the served-card render must carry Cache-Control: private, no-store"
    );

    // POST the draft form as a browser does (url-encoded body: business description + the hidden
    // issued caller key) -> 200 rendered CARD (HTML), carrying the drafted business name and a
    // fresh issued key in the "draft again" retry form; no empty placeholder is left.
    // FINDING 6(a): the POST submits the EXACT key the GET render issued (`get_key_1_chirho`), proving
    // the issued key is accepted end to end, not a hardcoded literal.
    let (draft_status_chirho, draft_body_chirho) = http_post_form_chirho(
        &base_chirho,
        &format!("/app-chirho/{APP_NAME_CHIRHO}/{DRAFT_ROUTE_CHIRHO}"),
        &session_cookie_chirho,
        &draft_form_body_chirho(pii_needle_chirho, &get_key_1_chirho),
    );
    assert_eq!(
        draft_status_chirho,
        200,
        "POST a valid brief to the draft route must complete with 200 (body: {})",
        String::from_utf8_lossy(&draft_body_chirho)
    );
    assert!(
        contains_subslice_chirho(&draft_body_chirho, b"<!doctype html>"),
        "the POST returns the rendered HTML card, not raw JSON"
    );
    assert!(
        contains_subslice_chirho(&draft_body_chirho, pii_needle_chirho.as_bytes()),
        "the rendered card served over HTTP must carry the drafted business name"
    );
    // ARM 2: the POST-result card's retry form ALSO carries a valid issued key.
    issued_caller_key_chirho(&draft_body_chirho, "the POST card");

    // FINDING 6(b) — SAME-KEY REPLAY: re-POST the EXACT same issued key AND the same brief. Delivery
    // repeats (200, the same drafted card) and settles NO second debit (the ladder below still shows one
    // charge for this key). MEASURED mechanism (gpt recert): the caller key selects a durable INVOCATION
    // FILE that RETAINS its original signed intent + journal cut; a same-key retry reuses that retained
    // cut, so the money key -- which binds the CONTENT request_ref PLUS the journal cut and verified
    // context, NOT a caller-key digest -- is unchanged and no new charge settles. This is retry
    // idempotency via the retained cut, not content-only dedup and not a caller key in the money
    // identity. The paid effect node is capability-bearing (not memoized), so the stub provider still
    // re-runs; the provider delta is captured/reported as a provider-CALL count only, never as a money
    // or persistence fact. (Same key + DIFFERENT brief is a separate collision refusal -- arm (e).)
    let provider_before_replay_chirho = provider_invocations_chirho.load(Ordering::SeqCst);
    let (replay_status_chirho, replay_body_chirho) = http_post_form_chirho(
        &base_chirho,
        &format!("/app-chirho/{APP_NAME_CHIRHO}/{DRAFT_ROUTE_CHIRHO}"),
        &session_cookie_chirho,
        &draft_form_body_chirho(pii_needle_chirho, &get_key_1_chirho),
    );
    assert_eq!(
        replay_status_chirho,
        200,
        "a same-key same-brief replay must return 200 (idempotent delivery), body: {}",
        String::from_utf8_lossy(&replay_body_chirho)
    );
    assert!(
        contains_subslice_chirho(&replay_body_chirho, pii_needle_chirho.as_bytes()),
        "the replay must return the same drafted card content"
    );
    let replay_provider_delta_chirho =
        provider_invocations_chirho.load(Ordering::SeqCst) - provider_before_replay_chirho;

    // FINDING 6(c) — ARM 4 (invocation-money identity, MEASURED SERIAL behavior, NOT desired law): a
    // FRESH caller key with the SAME brief. BOTH the old no-second-charge prediction AND the earlier
    // "caller key + content" conclusion were wrong (gpt recert executed the mechanism). The truth:
    // request_ref is CONTENT-ONLY, but the money key ALSO binds the current journal CUT; a fresh caller
    // key opens a NEW invocation file at the ADVANCED cut, so its money key differs from the first and a
    // new charge settles serially. The two completing intents here share request_ref but sit at cuts 1
    // and 3 (distinct money keys); making the second's cut equal the first makes the keys equal -- so
    // this is NOT proof of caller-key separation at an identical cut. a2c keeps TWO separate OPEN
    // obligations: account payer binding AND invocation-to-money binding. See the report flag.
    let provider_before_arm4_chirho = provider_invocations_chirho.load(Ordering::SeqCst);
    let (arm4_status_chirho, _arm4_body_chirho) = http_post_form_chirho(
        &base_chirho,
        &format!("/app-chirho/{APP_NAME_CHIRHO}/{DRAFT_ROUTE_CHIRHO}"),
        &session_cookie_chirho,
        &draft_form_body_chirho(pii_needle_chirho, "arm4-fresh-key-chirho"),
    );
    assert_eq!(
        arm4_status_chirho,
        200,
        "Arm 4 (fresh key, same brief) is served over HTTP, body: {}",
        String::from_utf8_lossy(&_arm4_body_chirho)
    );
    let arm4_provider_delta_chirho =
        provider_invocations_chirho.load(Ordering::SeqCst) - provider_before_arm4_chirho;

    // FINDING 4 — TYPED REFUSAL RE-RENDER over real HTTP: a fresh key with a brief that makes the
    // provider return a typed refusal (`ProviderUnavailableChirho`). The DAG completes with an
    // `llm-refusal-v1-chirho` output, and the pure render-card node renders an HONEST refusal card --
    // never a fake "Your draft is ready." success -- showing the fixed refusal message (which carries
    // NO amount) and a valid issued key in its retry form. The retry form's textarea is EMPTY; the
    // refusal does NOT preserve/echo the submitted brief (the earlier Option-A echo was not selected).
    // A provider refusal releases the whole Hold, so it settles NO charge (payer net unchanged below).
    let (refusal_status_chirho, refusal_body_chirho) = http_post_form_chirho(
        &base_chirho,
        &format!("/app-chirho/{APP_NAME_CHIRHO}/{DRAFT_ROUTE_CHIRHO}"),
        &session_cookie_chirho,
        &draft_form_body_chirho(PROVIDER_REFUSAL_MARKER_CHIRHO, "refusal-fresh-key-chirho"),
    );
    assert_eq!(
        refusal_status_chirho,
        200,
        "a typed provider refusal renders a card over HTTP (200), body: {}",
        String::from_utf8_lossy(&refusal_body_chirho)
    );
    assert!(
        contains_subslice_chirho(&refusal_body_chirho, b"We could not draft your page."),
        "the refusal card must render the honest refusal heading, not a success"
    );
    assert!(
        contains_subslice_chirho(&refusal_body_chirho, b"the drafting service is unavailable"),
        "the refusal card must show the typed refusal's fixed message"
    );
    assert!(
        !contains_subslice_chirho(&refusal_body_chirho, b"Your draft is ready."),
        "a typed refusal must NEVER render the success heading (Finding 4: no fake success)"
    );
    issued_caller_key_chirho(&refusal_body_chirho, "the refusal card");

    // AUTHORITY witness capture (reject BEFORE the effect): the provider counter is captured HERE,
    // after every non-rejected POST (happy, replay, Arm 4, refusal), and again after the negatives
    // below. The negatives must add ZERO provider invocations -- a claim the net balance cannot carry.
    let provider_before_negatives_chirho = provider_invocations_chirho.load(Ordering::SeqCst);

    // BOUNDARY NEGATIVES over the SAME running server. Every one must reject BEFORE the paid effect,
    // so the provider counter is unchanged across them and the money ladder shows ONE settled debit.

    // (a1) An unrelated app the served card never composed keeps the ORIGINAL behavior: it is not
    // servable here at all, so it is refused during request-context resolution (403) exactly as it
    // would be without the served-LLM composition — never a served-card path.
    let (unrelated_app_status_chirho, _unrelated_app_body_chirho) = http_post_form_chirho(
        &base_chirho,
        "/app-chirho/some-other-app-chirho/spend-chirho",
        &session_cookie_chirho,
        &draft_form_body_chirho("Unrelated-Co-Chirho", "unrelated-key-chirho"),
    );
    assert_eq!(
        unrelated_app_status_chirho, 403,
        "an unrelated app must keep its original request-context refusal, not a served-card path"
    );

    // (a2) The served app's OWN root under POST is not an eligible served surface (the render root is
    // GET, the paid route is POST draft-chirho). The admission returns NotServedCard, so it FALLS
    // THROUGH to the UNCHANGED elected dispatch and is refused there (Elected-era + PlatformRoot
    // tenant -> 503). This is the direct proof the fall-through preserves the original dispatch.
    // It is sent the way a script sends it, with the caller-key header, so the dispatch answers
    // with its plain status and identity; a browser form gets the same verdict as a 303 (the
    // carrier's relay arms pin that shape).
    let (fallthrough_status_chirho, _fallthrough_location_chirho, fallthrough_body_chirho) =
        http_post_form_raw_chirho(
            &base_chirho,
            &format!("/app-chirho/{APP_NAME_CHIRHO}/"),
            &session_cookie_chirho,
            &draft_form_body_chirho("Fallthrough-Co-Chirho", "fallthrough-key-chirho"),
            Some("fallthrough-key-chirho"),
        );
    assert_eq!(
        fallthrough_status_chirho, 503,
        "the served app's non-eligible POST surface must fall through to the unchanged dispatch"
    );
    assert!(
        contains_subslice_chirho(
            &fallthrough_body_chirho,
            b"RelayPlatformRootIdentityUnavailableChirho"
        ),
        "the fall-through must carry the UNCHANGED elected-dispatch refusal identity"
    );

    // (a3) A SECOND fully-deployed app with the SAME "draft-chirho" route name and a valid context:
    // the served dispatch is app-NAME-scoped, so this POST reaches the served-scope check, is NOT
    // admitted (NotServedCard), and falls through to the UNCHANGED dispatch (503 + dispatch identity)
    // -- NOT the early 403 a never-deployed app gets. This exercises route-scope, not just that an
    // unknown app is rejected somewhere.
    let (other_app_status_chirho, _other_app_location_chirho, other_app_body_chirho) =
        http_post_form_raw_chirho(
            &base_chirho,
            &format!("/app-chirho/{OTHER_APP_NAME_CHIRHO}/{DRAFT_ROUTE_CHIRHO}"),
            &session_cookie_chirho,
            &draft_form_body_chirho("Other-App-Witness-Co-Chirho", "other-app-key-chirho"),
            Some("other-app-key-chirho"),
        );
    assert_eq!(
        other_app_status_chirho, 503,
        "a second app with the same route name must fall through the served scope to the dispatch, \
         not be served and not die at an early 403"
    );
    assert!(
        contains_subslice_chirho(
            &other_app_body_chirho,
            b"RelayPlatformRootIdentityUnavailableChirho"
        ),
        "the second-app fall-through must carry the UNCHANGED elected-dispatch refusal identity"
    );

    // (b), (c), (d) use FRESH/UNIQUE brief bodies (distinct content hashes), NOT the happy body. Two
    // SEPARATE claims back these negatives, witnessed by DIFFERENT evidence:
    //   MONEY: the final ladder witnesses only "no ADDITIONAL NET SETTLED DEBIT" after the whole
    //     sequence. Fresh distinct bodies additionally remove a same-content confound. The balance does
    //     NOT witness absence of execution/persistence or a placed-then-cancelled Hold (nets to zero).
    //   AUTHORITY (reject before the PROVIDER): witnessed INDEPENDENTLY by the provider-invocation
    //     counter being UNCHANGED across these negatives -- provider-CALL evidence only; it does NOT
    //     prove no request/intent persistence or effect-machinery entry, and it is not a fixed total.
    // The caller key rides IN the url-encoded body (a browser form cannot set a header), so these
    // negatives vary the body's caller-key field. Each is a browser form, so its refusal is a 303 back
    // to the app's home (no Referer is sent) naming the invalid-key notice.
    let caller_key_invalid_location_chirho =
        format!("/app-chirho/{APP_NAME_CHIRHO}/#refusal-caller-key-invalid-chirho");

    // (b) Missing caller key (no field and no header) -> the 303 invalid-key notice.
    // FINDING 6(g): also a PRE-PROVIDER PERSISTENCE witness -- an admission-rejected negative must add
    // NO new public CAS object (no request/intent blob), proving it rejects before any DAG run /
    // effect / body persistence. The provider counter (unchanged across the negatives) and the
    // held==0 ladder check below carry the no-provider-call and no-Hold halves.
    let cas_before_missing_chirho = count_public_cas_objects_chirho(&canonical_root_chirho);
    let (missing_key_status_chirho, missing_location_chirho, _missing_body_chirho) =
        http_post_form_raw_chirho(
            &base_chirho,
            &format!("/app-chirho/{APP_NAME_CHIRHO}/{DRAFT_ROUTE_CHIRHO}"),
            &session_cookie_chirho,
            format!("{DESCRIPTION_FIELD_NAME_CHIRHO}=Missing-Key-Witness-Co-Chirho").as_bytes(),
            None,
        );
    assert_eq!(
        (
            missing_key_status_chirho,
            missing_location_chirho.as_deref()
        ),
        (303, Some(caller_key_invalid_location_chirho.as_str())),
        "a browser form with no caller key goes back to the app with the invalid-key notice"
    );
    assert_eq!(
        count_public_cas_objects_chirho(&canonical_root_chirho),
        cas_before_missing_chirho,
        "FINDING 6(g): an admission-rejected negative must persist NO new public CAS object"
    );

    // (c) Invalid caller key (a space, sent as %20) -> the 303 invalid-key notice.
    let (invalid_key_status_chirho, invalid_location_chirho, _invalid_body_chirho) =
        http_post_form_raw_chirho(
            &base_chirho,
            &format!("/app-chirho/{APP_NAME_CHIRHO}/{DRAFT_ROUTE_CHIRHO}"),
            &session_cookie_chirho,
            format!(
                "{DESCRIPTION_FIELD_NAME_CHIRHO}=Invalid-Key-Witness-Co-Chirho&\
                 {IDEMPOTENCY_KEY_FIELD_NAME_CHIRHO}=has%20space"
            )
            .as_bytes(),
            None,
        );
    assert_eq!(
        (
            invalid_key_status_chirho,
            invalid_location_chirho.as_deref()
        ),
        (303, Some(caller_key_invalid_location_chirho.as_str())),
        "a browser form with an invalid caller key goes back with the invalid-key notice"
    );
    // A script sends the key in the header instead, and keeps the card's plain status and identity.
    let (scripted_status_chirho, _scripted_location_chirho, scripted_body_chirho) =
        http_post_form_raw_chirho(
            &base_chirho,
            &format!("/app-chirho/{APP_NAME_CHIRHO}/{DRAFT_ROUTE_CHIRHO}"),
            &session_cookie_chirho,
            format!("{DESCRIPTION_FIELD_NAME_CHIRHO}=Scripted-Invalid-Witness-Co-Chirho")
                .as_bytes(),
            Some("has space"),
        );
    assert_eq!(
        scripted_status_chirho, 400,
        "a scripted invalid caller key must be 400"
    );
    assert!(
        contains_subslice_chirho(&scripted_body_chirho, b"ServedLlmCallerKeyInvalidChirho"),
        "a scripted invalid caller key must carry the invalid-key refusal identity"
    );

    // (d) Duplicate caller-key field (the field appears twice in the body) -> the 303 invalid-key
    // notice.
    let (duplicate_key_status_chirho, duplicate_location_chirho, _duplicate_body_chirho) =
        http_post_form_raw_chirho(
            &base_chirho,
            &format!("/app-chirho/{APP_NAME_CHIRHO}/{DRAFT_ROUTE_CHIRHO}"),
            &session_cookie_chirho,
            format!(
                "{DESCRIPTION_FIELD_NAME_CHIRHO}=Duplicate-Key-Witness-Co-Chirho&\
                 {IDEMPOTENCY_KEY_FIELD_NAME_CHIRHO}=dup-key-a-chirho&\
                 {IDEMPOTENCY_KEY_FIELD_NAME_CHIRHO}=dup-key-b-chirho"
            )
            .as_bytes(),
            None,
        );
    assert_eq!(
        (
            duplicate_key_status_chirho,
            duplicate_location_chirho.as_deref()
        ),
        (303, Some(caller_key_invalid_location_chirho.as_str())),
        "a browser form with a doubled caller-key field goes back with the invalid-key notice"
    );

    // (e) Conflicting caller key: the SAME key as the happy POST but a DIFFERENT brief body binds to
    // different request evidence -> RelayCallerKeyCollisionChirho, rejected before a second charge.
    // The collision is a RUN-PATH refusal (the caller key passed admission as present/valid/unique),
    // so over HTTP it carries the GENERIC app-execution refusal body by the no-detail-leak design --
    // distinct from the admission-layer caller-key refusals (b/c/d) above. That distinction pins WHY
    // (e) was rejected: it reached the run path, not the caller-key admission. The exact
    // RelayCallerKeyCollisionChirho identity is pinned at the run path in
    // `run_intent_chirho/caller_key_tests_chirho.rs` and emitted to the server log.
    let (conflict_status_chirho, conflict_body_chirho) = http_post_form_chirho(
        &base_chirho,
        &format!("/app-chirho/{APP_NAME_CHIRHO}/{DRAFT_ROUTE_CHIRHO}"),
        &session_cookie_chirho,
        &draft_form_body_chirho("Different-Brief-Co-Chirho", &get_key_1_chirho),
    );
    assert_eq!(
        conflict_status_chirho, 400,
        "reusing the happy caller key with a different brief must be 400 (collision)"
    );
    assert!(
        contains_subslice_chirho(&conflict_body_chirho, b"CairnAppExecutionRefusedChirho")
            && !contains_subslice_chirho(&conflict_body_chirho, b"ServedLlmCallerKey"),
        "the conflict must be a run-path rejection (generic app-execution refusal), NOT an \
         admission-layer caller-key refusal"
    );

    // Stop the server gracefully: this drops the composition and its resident handle, releasing the
    // exclusive ledger lock before the read-only substrate read below opens the journal.
    stop_chirho.store(true, Ordering::Release);
    runtime_chirho
        .block_on(server_handle_chirho)
        .expect("join the served runtime task")
        .expect("the served runtime shut down cleanly");
    std::env::remove_var("CAIRN_DEV_LLM_SERVED_CHIRHO");

    // THE MONEY LADDER, via the ledger-host substrate read a2's own proof uses.
    let port_read_chirho = LedgerHostProjectionReadPortChirho::open_existing_chirho(
        &canonical_root_chirho,
        &config_path_chirho,
        &ledger_host_chirho,
    )
    .expect("open the durable ledger host read door");
    let balances_chirho = port_read_chirho
        .read_substrate_balances_chirho()
        .expect("read verified substrate balances");

    let payer_key_chirho = (user_chirho.clone(), BILLING_KIND_CHIRHO.to_owned());
    let settlement_key_chirho = (
        SETTLEMENT_OWNER_CHIRHO.to_owned(),
        BILLING_KIND_CHIRHO.to_owned(),
    );
    let payer_net_chirho = balances_chirho
        .account_nets_chirho
        .get(&payer_key_chirho)
        .copied()
        .expect("payer has a ledger account");
    let settlement_net_chirho = balances_chirho
        .account_nets_chirho
        .get(&settlement_key_chirho)
        .copied()
        .unwrap_or(0);
    // MEASURED money ladder across all served POSTs: the happy POST and the same-key replay reused ONE
    // caller key (`get_key_1`), the fresh-key Arm 4 used a second, and the refusal POST used a third the
    // provider REFUSED. Exactly TWO charges settle -- the two distinct caller keys whose drafts
    // COMPLETED (happy + Arm 4). MECHANISM (gpt recert): the money key binds the CONTENT request_ref
    // plus the journal CUT (not a caller-key digest); a fresh completing key opens a new invocation file
    // at the advanced cut and settles a new charge, while the same-key replay reuses its invocation
    // file's retained cut and settles nothing (Finding 6(b)); the refusal released its Hold (Finding 4).
    // Conservation holds: payer debit == settlement credit == two fixed per-draft prices, supply fixed.
    const DISTINCT_CALLER_KEY_CHARGES_CHIRHO: u64 = 2;
    let expected_debit_chirho = DISTINCT_CALLER_KEY_CHARGES_CHIRHO * LLM_PRICE_CHIRHO;
    assert_eq!(
        payer_net_chirho,
        AMOUNT_CHIRHO - expected_debit_chirho,
        "payer net must be the minted amount minus one price per DISTINCT caller key (2 charges)"
    );
    assert_eq!(
        settlement_net_chirho, expected_debit_chirho,
        "settlement owner must be credited one price per distinct caller key (2 charges)"
    );
    let payer_debit_chirho = AMOUNT_CHIRHO - payer_net_chirho;
    assert_eq!(
        payer_debit_chirho, settlement_net_chirho,
        "the served leg conserves money over HTTP: payer debit equals settlement credit"
    );
    assert_eq!(
        payer_debit_chirho, expected_debit_chirho,
        "exactly one fixed per-draft price per distinct caller key moved from payer to settlement"
    );
    assert_eq!(
        balances_chirho
            .net_supply_by_kind_chirho
            .get(BILLING_KIND_CHIRHO)
            .copied(),
        Some(AMOUNT_CHIRHO),
        "supply is conserved: a within-kind settlement never changes minted supply"
    );
    assert!(
        balances_chirho
            .account_held_chirho
            .values()
            .all(|held_chirho| *held_chirho == 0),
        "no Hold remains anywhere after the draft Finalizes"
    );

    // AUTHORITY witness (reject before the PROVIDER): the provider counter is UNCHANGED across every
    // negative (unrelated app, second-app route-scope, missing/invalid/duplicate/conflict caller key).
    // This is provider-CALL evidence ONLY: it proves the negatives did not reach the provider; it does
    // NOT prove no request/intent persistence and no entry into the effect machinery. Public-CAS
    // persistence for one negative is checked separately by the F6(g) missing-key witness above (public
    // CAS only). The happy POST invoked the provider at least once.
    let provider_after_all_chirho = provider_invocations_chirho.load(Ordering::SeqCst);
    assert_eq!(
        provider_after_all_chirho, provider_before_negatives_chirho,
        "the negatives must add ZERO provider invocations (reject before the effect)"
    );
    assert!(
        provider_before_replay_chirho >= 1,
        "the happy POST must have invoked the provider at least once"
    );
    // MEASURED money mechanism (recorded, NOT desired law): a same-content re-POST re-invokes the
    // capability-bearing (non-memoized) paid effect, so the provider is called again. The money key
    // binds the CONTENT request_ref plus the journal CUT (not a caller-key digest): the same-key replay
    // reuses its invocation file's retained cut and settles no new charge (retry idempotency); a fresh
    // key opens a new invocation file at the advanced cut and settles a new charge. Both content-only
    // dedup and caller-key-in-money-identity are WRONG; a2c keeps account-payer and invocation-money
    // binding as two separate open obligations.
    eprintln!(
        "money mechanism (measured): same-key replay re-invoked the provider \
         {replay_provider_delta_chirho} time(s) with NO new charge (retained-cut retry idempotency); a \
         fresh key re-invoked it {arm4_provider_delta_chirho} time(s) and settled a NEW charge (new \
         invocation file at the advanced journal cut) -- money key binds content request_ref + cut, not \
         the caller key"
    );

    // FINDING 6(e) — VIEWER BINDING of the sealed completion (privacy beyond needle-absence): the
    // drafted completion rests only as a viewer-subject private blob. This candidate arm resolves the
    // sealed `LlmResponseChirho` value (NOT the final raw HTML card) AS THE VIEWER (the payer), confirms
    // it carries the drafted name, denies a DIFFERENT principal on that hash, and checks the plaintext
    // hash is not a public CAS object. Scope: this covers the sealed response value; gpt's independent
    // recert additionally resolved the actual `<!doctype html>` card bytes and the `description_chirho=`
    // input as the viewer and denied a second viewer there. Public-CAS checks do not inventory every
    // persisted private surface, and Question K (unkeyed handle in public traces) stays open.
    let verified_hashes_chirho = verified_private_dag_value_hashes_chirho(&canonical_root_chirho)
        .expect("enumerate verified private DAG value hashes");
    let mut sealed_completion_hash_chirho = None;
    for hash_chirho in &verified_hashes_chirho {
        if let Ok(bytes_chirho) =
            load_private_dag_value_bytes_chirho(&canonical_root_chirho, &user_chirho, hash_chirho)
        {
            if let Ok(response_chirho) = serde_json::from_slice::<LlmResponseChirho>(&bytes_chirho)
            {
                if response_chirho
                    .completion_chirho
                    .contains(pii_needle_chirho)
                {
                    sealed_completion_hash_chirho = Some(hash_chirho.clone());
                    break;
                }
            }
        }
    }
    let sealed_completion_hash_chirho = sealed_completion_hash_chirho.expect(
        "the viewer must resolve its own sealed completion carrying the drafted business name",
    );
    let non_viewer_principal_chirho = format!("{user_chirho}-not-the-viewer-chirho");
    assert!(
        load_private_dag_value_bytes_chirho(
            &canonical_root_chirho,
            &non_viewer_principal_chirho,
            &sealed_completion_hash_chirho,
        )
        .is_err(),
        "FINDING 6(e): a non-viewer principal must NOT resolve the viewer's sealed completion"
    );
    assert!(
        cas_chirho::get_chirho(&canonical_root_chirho, &sealed_completion_hash_chirho).is_err(),
        "FINDING 6(e): the viewer's sealed completion must not be a public CAS object"
    );

    // ARM 6 (mandatory fail-closed CAS plaintext scan): the drafted business name (which rides both
    // the prompt and the completion) must NOT appear as plaintext at rest anywhere in the public CAS
    // -- prompt and completion are sealed as XChaCha20 private blobs (ciphertext only). Plaintext at
    // rest is an a2b BLOCKER, not a dev concession.
    let scanned_objects_chirho =
        assert_no_plaintext_needle_in_public_cas_chirho(&canonical_root_chirho, pii_needle_chirho);
    assert!(
        scanned_objects_chirho >= 3,
        "Arm 6 must scan the populated CAS (wasm, DAGs, node defs, ciphertext blobs), got {scanned_objects_chirho}"
    );

    // FINDING 3, attributed: the carrier strips its field before the run, so the SEALED request input the
    // viewer resolves carries the brief but never the raw issued key. The public-CAS scan below cannot
    // show this alone, because the draft route seals its whole body.
    let mut sealed_inputs_read_chirho = 0usize;
    for hash_chirho in &verified_hashes_chirho {
        let Ok(bytes_chirho) =
            load_private_dag_value_bytes_chirho(&canonical_root_chirho, &user_chirho, hash_chirho)
        else {
            continue;
        };
        assert!(
            !contains_subslice_chirho(&bytes_chirho, get_key_1_chirho.as_bytes()),
            "no sealed DAG value may carry the raw issued caller key"
        );
        if contains_subslice_chirho(&bytes_chirho, DESCRIPTION_FIELD_NAME_CHIRHO.as_bytes()) {
            sealed_inputs_read_chirho += 1;
        }
    }
    assert!(
        sealed_inputs_read_chirho >= 1,
        "the check must have read the sealed request input itself, got {sealed_inputs_read_chirho}"
    );

    // FINDING 3 (PUBLIC-CAS witness, scoped): the RAW submitted caller key does not rest in the PUBLIC
    // CAS. It is stripped from the DAG business input before persistence (only its digest rides run
    // identity), so scanning the public CAS for the exact issued key value finds ZERO occurrences
    // (fail-closed). Scope: this is a public-CAS check only; gpt's independent recert additionally
    // decrypted the recorded DAG values as the viewer and confirmed the raw key is absent from the
    // resolved private inputs (the non-vacuous check public-CAS absence alone cannot supply).
    let key_objects_scanned_chirho =
        assert_no_plaintext_needle_in_public_cas_chirho(&canonical_root_chirho, &get_key_1_chirho);
    assert!(
        key_objects_scanned_chirho >= 3,
        "the key-absence scan must read the populated CAS, got {key_objects_scanned_chirho}"
    );

    let _removed_chirho = std::fs::remove_dir_all(&root_chirho);
}

/// PROOF (GAP-1 wrong-root startup fence): a composition bound to root A refuses to serve a DIFFERENT
/// root. The fence passes on the composition's own bound root (root-match + test-kind both hold),
/// then the dev serve entry called with a wrong root returns the named mismatch refusal BEFORE any
/// startup recovery, router build, or listener bind.
#[test]
fn served_llm_dev_entry_refuses_a_root_the_composition_is_not_bound_to_chirho() {
    let _env_guard_chirho = A2B_SERVE_ENV_LOCK_CHIRHO
        .lock()
        .unwrap_or_else(|poison_chirho| poison_chirho.into_inner());
    let root_chirho = temp_root_chirho("fence-a");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let user_chirho = register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho)
        .expect("register a payer principal")
        .principal_chirho;
    let report_chirho = run_served_llm_dev_bootstrap_chirho(ServedLlmDevBootstrapRequestChirho {
        root_chirho: &root_chirho,
        payer_principal_chirho: &user_chirho,
        owner_principal_chirho: SETTLEMENT_OWNER_CHIRHO,
        amount_chirho: AMOUNT_CHIRHO,
        billing_kind_chirho: BILLING_KIND_CHIRHO,
    })
    .expect("a1 dev bootstrap funds the fence root");
    let canonical_root_chirho = root_chirho.canonicalize().expect("canonical fence root");
    let config_path_chirho = canonical_root_chirho.join(&report_chirho.config_file_chirho);
    let ledger_host_chirho = load_config_chirho(&config_path_chirho)
        .expect("load fence config")
        .ledger_host_chirho
        .expect("fence config carries a ledger host block");
    migrate_cas_lifecycle_offline_chirho(&canonical_root_chirho)
        .expect("initialize the CAS lifecycle on the fence root");

    let signer_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&ledger_host_chirho.signer_secrets_chirho)
            .expect("derive signer refs from config");
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&canonical_root_chirho, &signer_refs_chirho)
            .expect("load the runtime signers");
    let handle_chirho = testkind_normal_settlement_resident_opener_chirho(
        &canonical_root_chirho,
        &config_path_chirho,
        &ledger_host_chirho,
    )
    .expect("open the fence root through the dev-only door");
    let composition_chirho = open_shared_llm_served_composition_with_resident_journal_chirho(
        OpenSharedLlmServedCompositionParamsChirho {
            root_chirho: &canonical_root_chirho,
            handle_chirho,
            signers_chirho,
            provider_chirho: Box::new(StubLlmProviderChirho),
            policy_chirho: Box::new(AppPriceBookUserPaysLlmPolicyChirho),
            billing_kind_chirho: AssetKindIdChirho(BILLING_KIND_CHIRHO.to_owned()),
            ledger_config_chirho: &ledger_host_chirho,
            served_surface_chirho: ServedLlmCardSurfaceChirho::new_chirho(
                APP_NAME_CHIRHO,
                DRAFT_ROUTE_CHIRHO,
            ),
        },
    )
    .expect("compose the served-LLM runtime over the fence root");

    // FINDING 6(f) — exercise the STARTUP PATH, not just the helper. `verify_dev_startup_eligibility_
    // chirho` is the enforcement the dev serve entry calls before any recovery/router/bind. It PASSES
    // on the exact bound root (root-match AND a test-kind bound config both hold); the wrong-root half
    // below drives the SAME function through the serve entry and REFUSES, so deleting the root-match
    // check would fail this arm.
    composition_chirho
        .verify_dev_startup_eligibility_chirho(&canonical_root_chirho)
        .expect("the startup fence must pass on the composition's own bound root");

    // GAP-1 SECOND HALF (test-kind). MIGRATION NOTE / honest scope (gpt recert): ordinary (non-door)
    // resident openers DO exist (`runtime_actor_chirho.rs:911` returns the same handle type, and the
    // composition opener accepts a matching handle/config), so it is NOT that "no ordinary opener
    // exists." What blocks a non-test-kind bound composition here is a CONSTRUCTION-time refusal:
    // clearing the a1 fixture's marker and opening through the ordinary opener refuses during handle
    // construction ("a test-kind-chirho-prefixed kind issuer principal requires the test-kind marker"),
    // BEFORE startup. So the general same-root / non-test-kind STARTUP negative is UNEXECUTED; the
    // narrow accepted floor is the helper-negative below + the good-config startup pass above + the
    // wrong-root startup refusal. This is an a1-fixture constructor intercept, NOT universal constructor
    // impossibility. To close the general arm, drive `verify_dev_startup_eligibility_chirho(root)` on a
    // composition bound to a non-test-kind config and assert it REFUSES.
    let mut non_test_kind_config_chirho = ledger_host_chirho.clone();
    non_test_kind_config_chirho.test_kind_chirho = None;
    assert!(
        require_test_kind_marked_host_config_chirho(&non_test_kind_config_chirho).is_err(),
        "the startup fence's test-kind check must refuse a non-test-kind config on the correct root"
    );

    // A DIFFERENT root: the dev serve entry rejects it with the named mismatch refusal.
    let wrong_root_chirho = temp_root_chirho("fence-b");
    std::fs::create_dir_all(&wrong_root_chirho).unwrap();
    let canonical_wrong_root_chirho = wrong_root_chirho
        .canonicalize()
        .expect("canonical wrong root");
    let port_chirho = unused_loopback_port_chirho();
    std::env::set_var("CAIRN_DEV_LLM_SERVED_CHIRHO", "1");
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let result_chirho =
        runtime_chirho.block_on(serve_with_dev_llm_served_composition_until_chirho(
            &canonical_wrong_root_chirho,
            port_chirho,
            8,
            String::new(),
            String::new(),
            composition_chirho,
            Some(stop_chirho),
        ));
    std::env::remove_var("CAIRN_DEV_LLM_SERVED_CHIRHO");
    let error_text_chirho = format!(
        "{:#}",
        result_chirho.expect_err("serving a wrong root must fail closed")
    );
    assert!(
        error_text_chirho.contains(SERVED_LLM_DEV_ROOT_MISMATCH_REFUSAL_CHIRHO),
        "the wrong-root refusal must name the mismatch identity, got: {error_text_chirho}"
    );

    let _removed_a_chirho = std::fs::remove_dir_all(&root_chirho);
    let _removed_b_chirho = std::fs::remove_dir_all(&wrong_root_chirho);
}

/// PROOF (item 2, async-worker non-stall): the live-authority probe takes the composition with
/// `try_lock`, so while one draft holds the single composition (blocked in the provider), a
/// concurrent served POST is refused as a bounded busy refusal (503, no-detail wire) rather than
/// occupying an async worker for the whole provider duration. Uses a PAUSED provider, no spend.
#[test]
fn served_concurrent_post_is_refused_busy_while_a_draft_holds_the_composition_chirho() {
    let _env_guard_chirho = A2B_SERVE_ENV_LOCK_CHIRHO
        .lock()
        .unwrap_or_else(|poison_chirho| poison_chirho.into_inner());
    let root_chirho = temp_root_chirho("busy");
    std::fs::create_dir_all(&root_chirho).unwrap();

    let owner_chirho = register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
        .expect("register the app owner identity")
        .principal_chirho;
    let user_registration_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        USER_CREDENTIAL_CHIRHO,
    )
    .expect("register the payer user with a credential");
    let user_chirho = user_registration_chirho.principal_chirho;

    let report_chirho = run_served_llm_dev_bootstrap_chirho(ServedLlmDevBootstrapRequestChirho {
        root_chirho: &root_chirho,
        payer_principal_chirho: &user_chirho,
        owner_principal_chirho: SETTLEMENT_OWNER_CHIRHO,
        amount_chirho: AMOUNT_CHIRHO,
        billing_kind_chirho: BILLING_KIND_CHIRHO,
    })
    .expect("a1 dev bootstrap must fund the payer");
    let canonical_root_chirho = root_chirho.canonicalize().expect("canonical root");
    let config_path_chirho = canonical_root_chirho.join(&report_chirho.config_file_chirho);
    let ledger_host_chirho = load_config_chirho(&config_path_chirho)
        .expect("load a1 config")
        .ledger_host_chirho
        .expect("a1 config carries a ledger host block");
    migrate_cas_lifecycle_offline_chirho(&canonical_root_chirho)
        .expect("initialize the CAS lifecycle");
    let login_chirho = login_identity_with_credential_chirho(
        &canonical_root_chirho,
        &user_chirho,
        USER_CREDENTIAL_CHIRHO,
    )
    .expect("log the payer user in");
    let session_cookie_chirho = format!(
        "{SESSION_COOKIE_NAME_CHIRHO}={}:{}",
        user_chirho, login_chirho.token_chirho
    );

    let bytes_schema_chirho = cas_chirho::add_chirho(&canonical_root_chirho, b"bytes").unwrap();
    let render_wasm_chirho = build_and_read_guest_wasm_chirho("render_form_guest_chirho");
    let render_impl_chirho =
        cas_chirho::add_chirho(&canonical_root_chirho, &render_wasm_chirho).unwrap();
    let render_node_chirho = NodeDefChirho {
        name_chirho: "render-form-node-chirho".to_owned(),
        impl_wasm_chirho: render_impl_chirho,
        entry_chirho: "render_form_chirho".to_owned(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        capabilities_chirho: Vec::new(),
        fuel_limit_chirho: 200_000_000,
        ..NodeDefChirho::default()
    };
    let render_node_hash_chirho =
        store_chirho::put_object_chirho(&canonical_root_chirho, &render_node_chirho).unwrap();
    let root_dag_hash_chirho = store_chirho::put_object_chirho(
        &canonical_root_chirho,
        &DagChirho {
            nodes_chirho: vec![render_node_hash_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    let llm_node_chirho = NodeDefChirho {
        name_chirho: "draft-llm-node-chirho".to_owned(),
        impl_wasm_chirho: cas_chirho::add_chirho(&canonical_root_chirho, b"draft-llm-node-chirho")
            .unwrap(),
        entry_chirho: "draft_llm_chirho".to_owned(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        capabilities_chirho: vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: LLM_SERVED_EFFECT_SUBTYPE_CHIRHO.to_owned(),
            caller_chirho: "served-llm-card-http-runtime-chirho".to_owned(),
        }],
        effect_contract_set_chirho: Some(effect_contract_set_chirho()),
        fuel_limit_chirho: 0,
        ..NodeDefChirho::default()
    };
    let llm_node_hash_chirho =
        store_chirho::put_object_chirho(&canonical_root_chirho, &llm_node_chirho).unwrap();

    // Phase 3: a PURE build node turns the url-encoded form submission into the llm-request-v1 the
    // paid effect consumes -- reading ONLY the description (the caller key is dropped, never in the
    // prompt). Its output inherits the sealed form body's private subject, so the intermediate request
    // is sealed too (never public CAS). The route DAG runs build -> llm over one edge.
    let build_wasm_chirho = build_and_read_guest_wasm_chirho("build_llm_request_guest_chirho");
    let build_node_chirho = NodeDefChirho {
        name_chirho: "build-llm-request-node-chirho".to_owned(),
        impl_wasm_chirho: cas_chirho::add_chirho(&canonical_root_chirho, &build_wasm_chirho)
            .unwrap(),
        entry_chirho: "build_llm_request_chirho".to_owned(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        capabilities_chirho: Vec::new(),
        fuel_limit_chirho: 200_000_000,
        ..NodeDefChirho::default()
    };
    let build_node_hash_chirho =
        store_chirho::put_object_chirho(&canonical_root_chirho, &build_node_chirho).unwrap();

    // Phase 4: a PURE render-card node turns the sealed llm-response into the drafted card HTML with a
    // "draft again" retry form (carrying the empty caller-key placeholder the engine fills). It inherits the sealed
    // viewer subject, so the card is sealed at rest. The route DAG runs build -> llm -> render_card.
    let render_card_wasm_chirho = build_and_read_guest_wasm_chirho("render_card_guest_chirho");
    let render_card_node_chirho = NodeDefChirho {
        name_chirho: "render-card-node-chirho".to_owned(),
        impl_wasm_chirho: cas_chirho::add_chirho(&canonical_root_chirho, &render_card_wasm_chirho)
            .unwrap(),
        entry_chirho: "render_card_chirho".to_owned(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_owned(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        capabilities_chirho: Vec::new(),
        fuel_limit_chirho: 200_000_000,
        ..NodeDefChirho::default()
    };
    let render_card_node_hash_chirho =
        store_chirho::put_object_chirho(&canonical_root_chirho, &render_card_node_chirho).unwrap();
    let route_dag_hash_chirho = store_chirho::put_object_chirho(
        &canonical_root_chirho,
        &DagChirho {
            nodes_chirho: vec![
                build_node_hash_chirho.clone(),
                llm_node_hash_chirho.clone(),
                render_card_node_hash_chirho.clone(),
            ],
            edges_chirho: vec![
                EdgeChirho {
                    from_node_chirho: build_node_hash_chirho,
                    from_port_chirho: "out".to_owned(),
                    to_node_chirho: llm_node_hash_chirho.clone(),
                    to_port_chirho: "in".to_owned(),
                    privacy_chirho: None,
                },
                EdgeChirho {
                    from_node_chirho: llm_node_hash_chirho,
                    from_port_chirho: "out".to_owned(),
                    to_node_chirho: render_card_node_hash_chirho,
                    to_port_chirho: "in".to_owned(),
                    privacy_chirho: None,
                },
            ],
        },
    )
    .unwrap();

    let signer_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&ledger_host_chirho.signer_secrets_chirho)
            .expect("derive signer refs");
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&canonical_root_chirho, &signer_refs_chirho)
            .expect("load the runtime signers");
    let handle_chirho = testkind_normal_settlement_resident_opener_chirho(
        &canonical_root_chirho,
        &config_path_chirho,
        &ledger_host_chirho,
    )
    .expect("open a1's durable test-kind root through the dev-only door");

    deploy_app_with_head_transition_authority_chirho(
        &canonical_root_chirho,
        APP_NAME_CHIRHO,
        root_dag_hash_chirho,
        &owner_chirho,
        handle_chirho.head_transition_authority_chirho(),
    )
    .expect("deploy the served-LLM card app");
    deploy_app_route_with_head_transition_authority_chirho(
        &canonical_root_chirho,
        APP_NAME_CHIRHO,
        DRAFT_ROUTE_CHIRHO,
        route_dag_hash_chirho,
        &owner_chirho,
        handle_chirho.head_transition_authority_chirho(),
    )
    .expect("deploy the draft POST route");
    set_app_input_policy_chirho(
        &canonical_root_chirho,
        APP_NAME_CHIRHO,
        None,
        &owner_chirho,
        AppInputModeChirho::PlainChirho,
    )
    .expect("set the render root input policy");
    set_app_input_policy_chirho(
        &canonical_root_chirho,
        APP_NAME_CHIRHO,
        Some(DRAFT_ROUTE_CHIRHO),
        &owner_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: REQUEST_USER_PRIVATE_INPUT_SUBJECT_CHIRHO.to_owned(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .expect("set the draft route input policy");
    let _price_book_chirho = set_price_book_with_head_transition_authority_chirho(
        &canonical_root_chirho,
        APP_NAME_CHIRHO,
        &owner_chirho,
        None,
        BTreeMap::from([(
            LLM_SERVED_EFFECT_SUBTYPE_CHIRHO.to_owned(),
            LLM_PRICE_CHIRHO as i64,
        )]),
        0,
        handle_chirho.head_transition_authority_chirho(),
    )
    .expect("set the served-LLM price book");

    // A provider that blocks (holding the composition) until released, so one draft can hold the
    // single composition while a concurrent POST is fired.
    let (entered_tx_chirho, entered_rx_chirho) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx_chirho, release_rx_chirho) = std::sync::mpsc::channel::<()>();
    let composition_chirho = open_shared_llm_served_composition_with_resident_journal_chirho(
        OpenSharedLlmServedCompositionParamsChirho {
            root_chirho: &canonical_root_chirho,
            handle_chirho,
            signers_chirho,
            provider_chirho: Box::new(PausableStubProviderChirho {
                entered_tx_chirho,
                release_rx_chirho: std::sync::Mutex::new(release_rx_chirho),
            }),
            policy_chirho: Box::new(AppPriceBookUserPaysLlmPolicyChirho),
            billing_kind_chirho: AssetKindIdChirho(BILLING_KIND_CHIRHO.to_owned()),
            ledger_config_chirho: &ledger_host_chirho,
            served_surface_chirho: ServedLlmCardSurfaceChirho::new_chirho(
                APP_NAME_CHIRHO,
                DRAFT_ROUTE_CHIRHO,
            ),
        },
    )
    .expect("compose the served-LLM runtime over the fenced resident handle");

    let port_chirho = unused_loopback_port_chirho();
    let base_chirho = format!("http://127.0.0.1:{port_chirho}");
    std::env::set_var("CAIRN_DEV_LLM_SERVED_CHIRHO", "1");
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let server_root_chirho = canonical_root_chirho.clone();
    let server_stop_chirho = stop_chirho.clone();
    let server_handle_chirho = runtime_chirho.spawn(async move {
        serve_with_dev_llm_served_composition_until_chirho(
            &server_root_chirho,
            port_chirho,
            8,
            String::new(),
            String::new(),
            composition_chirho,
            Some(server_stop_chirho),
        )
        .await
    });
    wait_for_serve_health_chirho(&base_chirho);

    // Request A: POST the paid route on a thread. It enters the provider (holding the composition)
    // and blocks until released.
    let draft_path_chirho = format!("/app-chirho/{APP_NAME_CHIRHO}/{DRAFT_ROUTE_CHIRHO}");
    let a_base_chirho = base_chirho.clone();
    let a_cookie_chirho = session_cookie_chirho.clone();
    let a_path_chirho = draft_path_chirho.clone();
    let a_body_chirho = draft_form_body_chirho("Busy-Draft-A-Co-Chirho", "busy-key-a-chirho");
    let a_handle_chirho = std::thread::spawn(move || {
        http_post_form_chirho(
            &a_base_chirho,
            &a_path_chirho,
            &a_cookie_chirho,
            &a_body_chirho,
        )
    });

    // A is now inside the provider, holding the composition lock.
    entered_rx_chirho
        .recv_timeout(Duration::from_secs(20))
        .expect("draft A must enter the provider holding the composition lock");

    // Request B: a concurrent POST must be refused BUSY, not stalled waiting for A's draft to finish.
    // It is a browser form, so the refusal is the 303 write-unavailable notice (no detail).
    let (b_status_chirho, b_location_chirho, _b_body_chirho) = http_post_form_raw_chirho(
        &base_chirho,
        &draft_path_chirho,
        &session_cookie_chirho,
        &draft_form_body_chirho("Busy-Draft-B-Co-Chirho", "busy-key-b-chirho"),
        None,
    );
    assert_eq!(
        (b_status_chirho, b_location_chirho.as_deref()),
        (
            303,
            Some(
                format!("/app-chirho/{APP_NAME_CHIRHO}/#refusal-write-unavailable-chirho").as_str()
            )
        ),
        "a concurrent POST while a draft holds the composition must be refused busy, not stalled"
    );

    // Release A: it completes with 200 (the composition was never corrupted, just serialized).
    release_tx_chirho.send(()).expect("release draft A");
    let (a_status_chirho, _a_body_chirho) = a_handle_chirho.join().expect("join draft A thread");
    assert_eq!(a_status_chirho, 200, "draft A completes after release");

    stop_chirho.store(true, Ordering::Release);
    runtime_chirho
        .block_on(server_handle_chirho)
        .expect("join the served runtime task")
        .expect("the served runtime shut down cleanly");
    std::env::remove_var("CAIRN_DEV_LLM_SERVED_CHIRHO");
    let _removed_chirho = std::fs::remove_dir_all(&root_chirho);
}
