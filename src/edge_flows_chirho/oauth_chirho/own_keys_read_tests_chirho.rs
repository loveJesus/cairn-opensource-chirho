// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K3's engine arms, through the real store door: the owner's keys read answers her own rows (a limited key's as its
//! actions), private to her and never in public CAS; a list that cannot be read answers `unavailable-chirho`, never an
//! empty list; only a browser session reads; and no other store road reads or writes the namespace.
//! Workflow: the owner's keys page (K3),
//! `spec-chirho/workflows-chirho/identity-auth-chirho/own-keys-page-chirho.md`.

use super::*;
use crate::dag_private_value_chirho;
use crate::effect_chirho::{run_effect_with_context_chirho, SCOPED_WRITE_STORE_SCHEMA_CHIRHO};
use crate::model_chirho::{
    CapabilityChirho, DagChirho, EffectChirho, HashChirho, NodeDefChirho, RequestContextChirho,
    RequestKeyLimitChirho,
};
use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use cairn_capability_chirho::capability_key_grant_chirho::{
    LIMITED_KEY_GRANTS_DIGEST_SCOPE_PREFIX_CHIRHO, LIMITED_KEY_SCOPE_MARKER_CHIRHO,
    OWN_KEYS_CAPABILITY_PREFIX_CHIRHO,
};
use cairn_model_app_chirho::AppKeyAuthorityRouteChirho;
use identity_chirho::PrincipalKindChirho;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

const OPENED_APP_CHIRHO: &str = "keyed";
const PLAIN_APP_CHIRHO: &str = "plain";
const SECRET_CHIRHO: &str = "own-keys-read-secret-chirho";
const PAGE_KEY_CHIRHO: &str = "page-document-chirho";
const PAGE_READ_CHIRHO: &str = "page-read-chirho";
const PAGE_SAVE_CHIRHO: &str = "page-save-chirho";
/// The fields a row may carry, and no other: never the key, its hash, its seq or its session.
const ROW_FIELDS_CHIRHO: [&str; 7] = [
    "app_chirho",
    "expires_ms_chirho",
    "issued_ms_chirho",
    "key_id_chirho",
    "live_chirho",
    "rate_limit_chirho",
    "scopes_chirho",
];

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-own-keys-read-{label_chirho}-{}-{}-{}",
        std::process::id(),
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed),
        now_ms_chirho()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn viewer_state_chirho(write_chirho: bool) -> CapabilityChirho {
    let prefix_chirho = "viewer-state-chirho/".to_string();
    if write_chirho {
        CapabilityChirho::WriteStoreChirho { prefix_chirho }
    } else {
        CapabilityChirho::ReadStoreChirho { prefix_chirho }
    }
}

/// A one-node DAG holding `capabilities_chirho`, stored; `label_chirho` keeps each DAG's identity distinct.
fn dag_chirho(
    root_chirho: &Path,
    label_chirho: &str,
    capabilities_chirho: Vec<CapabilityChirho>,
) -> HashChirho {
    let wasm_chirho = cas_chirho::add_chirho(root_chirho, label_chirho.as_bytes()).unwrap();
    let node_chirho = crate::store_chirho::put_object_chirho(
        root_chirho,
        &NodeDefChirho {
            name_chirho: label_chirho.to_string(),
            impl_wasm_chirho: wasm_chirho,
            entry_chirho: "run_chirho".to_string(),
            capabilities_chirho,
            ..Default::default()
        },
    )
    .unwrap();
    crate::store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap()
}

/// Two apps of one owner: `keyed`, opened to limited keys for page-read and page-save, and `plain`, unopened, so it
/// still issues legacy keys. Each has its oauth client.
struct WorldChirho {
    root_chirho: PathBuf,
    owner_chirho: String,
    keyed_client_chirho: OauthClientRecordChirho,
    plain_client_chirho: OauthClientRecordChirho,
}

fn world_chirho(label_chirho: &str) -> WorldChirho {
    let root_chirho = tmp_root_chirho(label_chirho);
    let owner_chirho =
        identity_chirho::register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
            .unwrap()
            .principal_chirho;
    let home_chirho = dag_chirho(&root_chirho, "home", vec![viewer_state_chirho(false)]);
    let view_chirho = dag_chirho(&root_chirho, "view", vec![viewer_state_chirho(false)]);
    let save_chirho = dag_chirho(
        &root_chirho,
        "save",
        vec![viewer_state_chirho(false), viewer_state_chirho(true)],
    );
    let deploy_chirho = |app_chirho: &str| {
        crate::app_chirho::deploy_app_chirho(
            &root_chirho,
            app_chirho,
            home_chirho.clone(),
            &owner_chirho,
        )
        .unwrap();
    };
    deploy_chirho(OPENED_APP_CHIRHO);
    deploy_chirho(PLAIN_APP_CHIRHO);
    for (route_chirho, dag_hash_chirho) in [("view", &view_chirho), ("save", &save_chirho)] {
        crate::app_chirho::deploy_app_route_chirho(
            &root_chirho,
            OPENED_APP_CHIRHO,
            route_chirho,
            dag_hash_chirho.clone(),
            &owner_chirho,
        )
        .unwrap();
    }
    let keyed_client_chirho =
        register_client_chirho(&root_chirho, OPENED_APP_CHIRHO, &owner_chirho).unwrap();
    let plain_client_chirho =
        register_client_chirho(&root_chirho, PLAIN_APP_CHIRHO, &owner_chirho).unwrap();
    crate::app_chirho::append_app_key_authority_record_chirho(
        &root_chirho,
        OPENED_APP_CHIRHO,
        &owner_chirho,
        vec![
            AppKeyAuthorityRouteChirho {
                route_chirho: "save".to_string(),
                action_chirho: PAGE_SAVE_CHIRHO.to_string(),
                dag_chirho: save_chirho,
                resources_chirho: vec![PAGE_KEY_CHIRHO.to_string()],
            },
            AppKeyAuthorityRouteChirho {
                route_chirho: "view".to_string(),
                action_chirho: PAGE_READ_CHIRHO.to_string(),
                dag_chirho: view_chirho,
                resources_chirho: vec![PAGE_KEY_CHIRHO.to_string()],
            },
        ],
    )
    .unwrap();
    WorldChirho {
        root_chirho,
        owner_chirho,
        keyed_client_chirho,
        plain_client_chirho,
    }
}

impl WorldChirho {
    fn user_chirho(&self) -> String {
        identity_chirho::register_identity_with_credential_chirho(
            &self.root_chirho,
            PrincipalKindChirho::UserChirho,
            SECRET_CHIRHO,
        )
        .unwrap()
        .principal_chirho
    }

    /// A legacy key on the unopened app.
    fn legacy_chirho(&self, principal_chirho: &str) -> ScopedTokenIssueChirho {
        issue_scoped_token_with_rate_limit_chirho(
            &self.root_chirho,
            principal_chirho,
            SECRET_CHIRHO,
            &self.plain_client_chirho.client_id_chirho,
            vec!["invoke_chirho".to_string()],
            Some(public_default_rate_limit_chirho()),
        )
        .unwrap()
    }

    /// A limited key on the opened app, holding `actions_chirho`.
    fn limited_chirho(
        &self,
        principal_chirho: &str,
        actions_chirho: &[&str],
    ) -> ScopedTokenIssueChirho {
        issue_limited_key_chirho(
            &self.root_chirho,
            principal_chirho,
            SECRET_CHIRHO,
            &self.keyed_client_chirho.client_id_chirho,
            &actions_chirho
                .iter()
                .map(|action_chirho| action_chirho.to_string())
                .collect::<Vec<_>>(),
            None,
        )
        .unwrap()
    }

    /// The context the host builds for her signed-in browser on the opened app.
    fn browser_chirho(&self, principal_chirho: &str) -> RequestContextChirho {
        RequestContextChirho {
            user_principal_chirho: principal_chirho.to_string(),
            app_chirho: OPENED_APP_CHIRHO.to_string(),
            owner_principal_chirho: self.owner_chirho.clone(),
            client_id_chirho: BROWSER_SESSION_CLIENT_ID_CHIRHO.to_string(),
            token_hash_chirho: "browser-session-token-hash-chirho".to_string(),
            price_book_chirho: None,
            billing_policy_chirho: None,
            key_limit_chirho: None,
        }
    }
}

fn request_chirho() -> serde_json::Value {
    serde_json::json!({ "schema_chirho": OWN_KEYS_READ_REQUEST_SCHEMA_CHIRHO })
}

fn read_store_chirho(prefix_chirho: &str) -> CapabilityChirho {
    CapabilityChirho::ReadStoreChirho {
        prefix_chirho: prefix_chirho.to_string(),
    }
}

/// One store effect through the real door; `seq_chirho` also names its idempotency key.
fn effect_chirho(
    root_chirho: &Path,
    seq_chirho: u64,
    capability_chirho: CapabilityChirho,
    request_bytes_chirho: &[u8],
    context_chirho: Option<&RequestContextChirho>,
) -> Result<EffectChirho> {
    run_effect_with_context_chirho(
        root_chirho,
        seq_chirho,
        HashChirho(format!("own-keys-read-{seq_chirho}-chirho")),
        capability_chirho,
        request_bytes_chirho,
        context_chirho,
    )
}

/// The answer of a read, loaded from the viewer's private value plane.
fn answer_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    effect_chirho: &EffectChirho,
) -> serde_json::Value {
    let response_chirho = effect_chirho.response_chirho.as_ref().unwrap();
    // Not in public CAS. `is_err` alone cannot tell absent from unreadable; nothing in this fresh root makes an object
    // unreadable, and the plaintext scan in the caller is a second, independent instrument.
    assert!(cas_chirho::get_chirho(root_chirho, response_chirho).is_err());
    let bytes_chirho = dag_private_value_chirho::load_private_dag_value_bytes_chirho(
        root_chirho,
        principal_chirho,
        response_chirho,
    )
    .unwrap();
    serde_json::from_slice(&bytes_chirho).unwrap()
}

/// Every file under `root_chirho` whose bytes contain `needle_chirho`.
fn files_containing_chirho(root_chirho: &Path, needle_chirho: &[u8]) -> Vec<PathBuf> {
    let mut hits_chirho = Vec::new();
    let mut pending_chirho = vec![root_chirho.to_path_buf()];
    while let Some(dir_chirho) = pending_chirho.pop() {
        for entry_chirho in std::fs::read_dir(&dir_chirho).unwrap().flatten() {
            let path_chirho = entry_chirho.path();
            if path_chirho.is_dir() {
                pending_chirho.push(path_chirho);
            } else if std::fs::read(&path_chirho).is_ok_and(|bytes_chirho| {
                bytes_chirho
                    .windows(needle_chirho.len())
                    .any(|window_chirho| window_chirho == needle_chirho)
            }) {
                hits_chirho.push(path_chirho);
            }
        }
    }
    hits_chirho
}

fn refusal_chirho(result_chirho: Result<EffectChirho>) -> String {
    format!(
        "{:#}",
        result_chirho.expect_err("the read must be refused, not answered")
    )
}

/// Rewrite the last line of the scoped-token log through `edit_chirho`.
fn edit_last_token_line_chirho(
    root_chirho: &Path,
    edit_chirho: impl FnOnce(&mut serde_json::Value),
) {
    let path_chirho = scoped_tokens_path_chirho(root_chirho);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    let mut lines_chirho: Vec<String> = text_chirho.lines().map(str::to_string).collect();
    let mut value_chirho: serde_json::Value =
        serde_json::from_str(lines_chirho.last().unwrap()).unwrap();
    edit_chirho(&mut value_chirho);
    *lines_chirho.last_mut().unwrap() = serde_json::to_string(&value_chirho).unwrap();
    std::fs::write(&path_chirho, format!("{}\n", lines_chirho.join("\n"))).unwrap();
}

#[test]
fn her_keys_read_answers_her_own_rows_private_to_her_with_a_limited_keys_actions_chirho() {
    let world_chirho = world_chirho("available");
    let root_chirho = &world_chirho.root_chirho;
    let her_chirho = world_chirho.user_chirho();
    let other_chirho = world_chirho.user_chirho();
    let legacy_chirho = world_chirho.legacy_chirho(&her_chirho);
    let limited_chirho =
        world_chirho.limited_chirho(&her_chirho, &[PAGE_SAVE_CHIRHO, PAGE_READ_CHIRHO]);
    let others_chirho = world_chirho.legacy_chirho(&other_chirho);
    let legacy_id_chirho = scoped_key_id_chirho(&token_hash_chirho(&legacy_chirho.token_chirho));
    let limited_id_chirho = scoped_key_id_chirho(&limited_key_chirho::limited_token_hash_chirho(
        &limited_chirho.token_chirho,
    ));
    let others_id_chirho = scoped_key_id_chirho(&token_hash_chirho(&others_chirho.token_chirho));

    let effect_chirho = effect_chirho(
        root_chirho,
        1,
        read_store_chirho(OWN_KEYS_CAPABILITY_PREFIX_CHIRHO),
        &serde_json::to_vec(&request_chirho()).unwrap(),
        Some(&world_chirho.browser_chirho(&her_chirho)),
    )
    .unwrap();
    let answer_chirho = answer_chirho(root_chirho, &her_chirho, &effect_chirho);
    assert_eq!(answer_chirho["schema_chirho"], OWN_KEYS_READ_SCHEMA_CHIRHO);
    assert_eq!(answer_chirho["state_chirho"], "available-chirho");
    let rows_chirho = answer_chirho["keys_chirho"].as_array().unwrap();
    // Her two keys, oldest first; never the other principal's.
    assert_eq!(rows_chirho.len(), 2);
    assert_eq!(rows_chirho[0]["key_id_chirho"], legacy_id_chirho);
    assert_eq!(rows_chirho[0]["app_chirho"], PLAIN_APP_CHIRHO);
    assert_eq!(
        rows_chirho[0]["scopes_chirho"],
        serde_json::json!(["invoke_chirho"])
    );
    assert_eq!(rows_chirho[1]["key_id_chirho"], limited_id_chirho);
    assert_eq!(rows_chirho[1]["app_chirho"], OPENED_APP_CHIRHO);
    // A limited key shows its actions, never its internal marker and digest scopes.
    assert_eq!(
        rows_chirho[1]["scopes_chirho"],
        serde_json::json!([PAGE_READ_CHIRHO, PAGE_SAVE_CHIRHO])
    );
    let answer_text_chirho = answer_chirho.to_string();
    assert!(!answer_text_chirho.contains(LIMITED_KEY_SCOPE_MARKER_CHIRHO));
    assert!(!answer_text_chirho.contains(LIMITED_KEY_GRANTS_DIGEST_SCOPE_PREFIX_CHIRHO));
    assert!(!answer_text_chirho.contains(others_id_chirho.as_str()));
    for row_chirho in rows_chirho {
        assert_eq!(row_chirho["live_chirho"], true);
        let fields_chirho: BTreeSet<&str> = row_chirho
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(fields_chirho, BTreeSet::from(ROW_FIELDS_CHIRHO));
    }
    // One row builder: the JSON list's rows are the same rows.
    assert_eq!(
        answer_chirho["keys_chirho"],
        serde_json::to_value(list_own_keys_chirho(root_chirho, &her_chirho).unwrap()).unwrap()
    );
    // Private to her: it loads under her subject and no other, and rests nowhere in plaintext.
    assert!(
        dag_private_value_chirho::load_private_dag_value_bytes_chirho(
            root_chirho,
            &other_chirho,
            effect_chirho.response_chirho.as_ref().unwrap(),
        )
        .is_err()
    );
    assert!(files_containing_chirho(root_chirho, limited_id_chirho.as_bytes()).is_empty());

    // A viewer with no keys reads an available, empty list: empty only when she has none.
    let none_chirho = world_chirho.user_chirho();
    let effect_chirho = self::effect_chirho(
        root_chirho,
        2,
        read_store_chirho(OWN_KEYS_CAPABILITY_PREFIX_CHIRHO),
        &serde_json::to_vec(&request_chirho()).unwrap(),
        Some(&world_chirho.browser_chirho(&none_chirho)),
    )
    .unwrap();
    assert_eq!(
        self::answer_chirho(root_chirho, &none_chirho, &effect_chirho),
        serde_json::json!({
            "schema_chirho": OWN_KEYS_READ_SCHEMA_CHIRHO,
            "state_chirho": "available-chirho",
            "keys_chirho": [],
        })
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn a_list_that_cannot_be_read_answers_unavailable_never_an_empty_list_chirho() {
    let unavailable_chirho = serde_json::json!({
        "schema_chirho": OWN_KEYS_READ_SCHEMA_CHIRHO,
        "state_chirho": "unavailable-chirho",
        "reason_chirho": OWN_KEYS_UNAVAILABLE_REASON_CHIRHO,
    });
    // A limited key whose grant set no longer matches its signed digest: the record's own signature still verifies,
    // so only the row builder's check can catch it, and it fails the list.
    let world_chirho = world_chirho("grant-tamper");
    let her_chirho = world_chirho.user_chirho();
    world_chirho.limited_chirho(&her_chirho, &[PAGE_READ_CHIRHO]);
    edit_last_token_line_chirho(&world_chirho.root_chirho, |line_chirho| {
        line_chirho["limited_grants_chirho"]["actions_chirho"][0]["action_chirho"] =
            serde_json::json!("account-admin-chirho");
    });
    let error_chirho = list_own_keys_chirho(&world_chirho.root_chirho, &her_chirho).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("grant set does not match its signed digest"),
        "{error_chirho:#}"
    );
    let effect_chirho = effect_chirho(
        &world_chirho.root_chirho,
        1,
        read_store_chirho(OWN_KEYS_CAPABILITY_PREFIX_CHIRHO),
        &serde_json::to_vec(&request_chirho()).unwrap(),
        Some(&world_chirho.browser_chirho(&her_chirho)),
    )
    .unwrap();
    let answer_chirho = answer_chirho(&world_chirho.root_chirho, &her_chirho, &effect_chirho);
    assert_eq!(answer_chirho, unavailable_chirho);
    assert!(answer_chirho.get("keys_chirho").is_none());
    let _ = std::fs::remove_dir_all(&world_chirho.root_chirho);

    // A key record whose signature fails: the token log itself does not verify.
    let world_chirho = self::world_chirho("log-tamper");
    let her_chirho = world_chirho.user_chirho();
    world_chirho.legacy_chirho(&her_chirho);
    edit_last_token_line_chirho(&world_chirho.root_chirho, |line_chirho| {
        line_chirho["scopes_chirho"] = serde_json::json!(["invoke_chirho", "admin_chirho"]);
    });
    assert!(list_own_keys_chirho(&world_chirho.root_chirho, &her_chirho).is_err());
    let effect_chirho = self::effect_chirho(
        &world_chirho.root_chirho,
        1,
        read_store_chirho(OWN_KEYS_CAPABILITY_PREFIX_CHIRHO),
        &serde_json::to_vec(&request_chirho()).unwrap(),
        Some(&world_chirho.browser_chirho(&her_chirho)),
    )
    .unwrap();
    assert_eq!(
        self::answer_chirho(&world_chirho.root_chirho, &her_chirho, &effect_chirho),
        unavailable_chirho
    );
    let _ = std::fs::remove_dir_all(&world_chirho.root_chirho);
}

#[test]
fn only_a_browser_session_reads_her_keys_chirho() {
    let world_chirho = world_chirho("browser-only");
    let root_chirho = &world_chirho.root_chirho;
    let her_chirho = world_chirho.user_chirho();
    let other_chirho = world_chirho.user_chirho();
    world_chirho.legacy_chirho(&her_chirho);
    let request_bytes_chirho = serde_json::to_vec(&request_chirho()).unwrap();
    let read_chirho =
        |seq_chirho: u64, bytes_chirho: &[u8], context_chirho: Option<&RequestContextChirho>| {
            effect_chirho(
                root_chirho,
                seq_chirho,
                read_store_chirho(OWN_KEYS_CAPABILITY_PREFIX_CHIRHO),
                bytes_chirho,
                context_chirho,
            )
        };

    assert!(refusal_chirho(read_chirho(1, &request_bytes_chirho, None))
        .contains("need a signed-in browser session"));
    // A key's context: its client id is its registered client's.
    let mut key_chirho = world_chirho.browser_chirho(&her_chirho);
    key_chirho.client_id_chirho = world_chirho.plain_client_chirho.client_id_chirho.clone();
    assert!(
        refusal_chirho(read_chirho(2, &request_bytes_chirho, Some(&key_chirho)))
            .contains("never by a key")
    );
    // A limited key's context carries its limit.
    let mut limited_chirho = world_chirho.browser_chirho(&her_chirho);
    limited_chirho.key_limit_chirho = Some(RequestKeyLimitChirho {
        action_chirho: PAGE_READ_CHIRHO.to_string(),
        resources_chirho: vec![PAGE_KEY_CHIRHO.to_string()],
    });
    assert!(
        refusal_chirho(read_chirho(3, &request_bytes_chirho, Some(&limited_chirho)))
            .contains("never by a key")
    );
    // A claimed principal is only checked for agreement.
    let browser_chirho = world_chirho.browser_chirho(&her_chirho);
    let mut claimed_chirho = request_chirho();
    claimed_chirho["user_principal_chirho"] = serde_json::json!(other_chirho);
    assert!(refusal_chirho(read_chirho(
        4,
        &serde_json::to_vec(&claimed_chirho).unwrap(),
        Some(&browser_chirho)
    ))
    .contains("claims a principal"));
    claimed_chirho["user_principal_chirho"] = serde_json::json!(her_chirho);
    claimed_chirho["app_params_chirho"] = serde_json::json!({});
    let effect_chirho = read_chirho(
        5,
        &serde_json::to_vec(&claimed_chirho).unwrap(),
        Some(&browser_chirho),
    )
    .unwrap();
    assert_eq!(
        answer_chirho(root_chirho, &her_chirho, &effect_chirho)["state_chirho"],
        "available-chirho"
    );
    // Any other field refuses: the request carries nothing else.
    let mut widened_chirho = request_chirho();
    widened_chirho["principal_chirho"] = serde_json::json!(other_chirho);
    assert!(read_chirho(
        6,
        &serde_json::to_vec(&widened_chirho).unwrap(),
        Some(&browser_chirho)
    )
    .is_err());
    // No registered client can carry a browser session's id: every client id is generated as `client/<hex>`.
    for client_chirho in [
        &world_chirho.keyed_client_chirho,
        &world_chirho.plain_client_chirho,
    ] {
        assert!(client_chirho.client_id_chirho.starts_with("client/"));
        assert_ne!(
            client_chirho.client_id_chirho,
            BROWSER_SESSION_CLIENT_ID_CHIRHO
        );
    }
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn no_other_store_road_reads_or_writes_the_owners_keys_chirho() {
    let world_chirho = world_chirho("reserved");
    let root_chirho = &world_chirho.root_chirho;
    let her_chirho = world_chirho.user_chirho();
    let browser_chirho = world_chirho.browser_chirho(&her_chirho);
    let own_keys_chirho = serde_json::to_vec(&request_chirho()).unwrap();
    let write_store_chirho = |prefix_chirho: &str| CapabilityChirho::WriteStoreChirho {
        prefix_chirho: prefix_chirho.to_string(),
    };
    let refused_chirho =
        |seq_chirho: u64, capability_chirho: CapabilityChirho, bytes_chirho: &[u8]| {
            refusal_chirho(effect_chirho(
                root_chirho,
                seq_chirho,
                capability_chirho,
                bytes_chirho,
                Some(&browser_chirho),
            ))
        };

    // A plain read of the prefix.
    assert!(refused_chirho(
        1,
        read_store_chirho(OWN_KEYS_CAPABILITY_PREFIX_CHIRHO),
        b"{}"
    )
    .contains("reserved own-keys capability prefix"));
    // The road itself, at any other prefix.
    for (seq_chirho, prefix_chirho) in [
        (2, "own-keys-chirho/someone-else/"),
        (3, "viewer-state-chirho/"),
    ] {
        assert!(refused_chirho(
            seq_chirho,
            read_store_chirho(prefix_chirho),
            &own_keys_chirho
        )
        .contains("exact capability prefix"));
    }
    // A write, plain or shaped as the road's request.
    for (seq_chirho, bytes_chirho) in [(4, b"{}".to_vec()), (5, own_keys_chirho.clone())] {
        assert!(refused_chirho(
            seq_chirho,
            write_store_chirho(OWN_KEYS_CAPABILITY_PREFIX_CHIRHO),
            &bytes_chirho
        )
        .contains("reserved own-keys capability prefix"));
    }
    // A scoped write from the broadest prefix, into the namespace, beside the control: the same write elsewhere lands.
    let scoped_chirho = |key_chirho: &str| {
        serde_json::to_vec(&serde_json::json!({
            "schema_chirho": SCOPED_WRITE_STORE_SCHEMA_CHIRHO,
            "key_chirho": key_chirho,
            "value_base64_chirho": BASE64_CHIRHO.encode(b"a-value-chirho"),
        }))
        .unwrap()
    };
    assert!(refused_chirho(
        6,
        write_store_chirho(""),
        &scoped_chirho("own-keys-chirho/forged-row-chirho")
    )
    .contains("cannot address the own-keys namespace"));
    effect_chirho(
        root_chirho,
        7,
        write_store_chirho(""),
        &scoped_chirho("notes-chirho/a-row-chirho"),
        Some(&browser_chirho),
    )
    .expect("the same scoped write outside the namespace lands");
    let _ = std::fs::remove_dir_all(root_chirho);
}
