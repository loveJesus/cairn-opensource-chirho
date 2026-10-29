// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K1's engine-level arms: a limited key lives under its own hash domain and an old-engine-compatible signed message,
//! its grant set cannot be tampered with or stripped into a legacy key, the key-authority log is sticky and fails closed,
//! an opening is bound to its reviewed DAG, retirement ends exactly an app's legacy keys, a limited key's run is never
//! resumed without its limit, and the key-authority view folds only what was appended.
//! Workflow: limited-key authority (K1),
//! `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.

use super::*;
use crate::model_chirho::{CapabilityChirho, DagChirho, HashChirho, NodeDefChirho};
use cairn_capability_chirho::capability_key_grant_chirho::{
    KeyRouteRefusalChirho, LIMITED_KEY_SCOPE_MARKER_CHIRHO,
};
use cairn_model_app_chirho::AppKeyAuthorityRouteChirho;
use identity_chirho::PrincipalKindChirho;
use std::sync::atomic::AtomicU64;

const APP_CHIRHO: &str = "keyed";
const PAGE_KEY_CHIRHO: &str = "page-document-chirho";

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho = COUNTER_CHIRHO.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-limited-key-{label_chirho}-{}-{n_chirho}-{}",
        std::process::id(),
        now_ms_chirho()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn viewer_read_chirho() -> CapabilityChirho {
    CapabilityChirho::ReadStoreChirho {
        prefix_chirho: "viewer-state-chirho/".to_string(),
    }
}

fn viewer_write_chirho() -> CapabilityChirho {
    CapabilityChirho::WriteStoreChirho {
        prefix_chirho: "viewer-state-chirho/".to_string(),
    }
}

/// A one-node DAG holding `capabilities_chirho`, stored; `label_chirho` keeps each DAG's identity distinct.
fn dag_with_chirho(
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

struct LimitedFixtureChirho {
    root_chirho: PathBuf,
    owner_chirho: String,
    client_chirho: OauthClientRecordChirho,
    view_dag_chirho: HashChirho,
    save_dag_chirho: HashChirho,
}

/// The app deployed with a root, a view route (a viewer-state read) and a save route (a read and a write), and its
/// oauth client. Nothing is opened yet.
fn fixture_chirho(label_chirho: &str) -> LimitedFixtureChirho {
    let root_chirho = tmp_root_chirho(label_chirho);
    let owner_chirho =
        identity_chirho::register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
            .unwrap()
            .principal_chirho;
    let home_dag_chirho = dag_with_chirho(&root_chirho, "home", vec![viewer_read_chirho()]);
    let view_dag_chirho = dag_with_chirho(&root_chirho, "view", vec![viewer_read_chirho()]);
    let save_dag_chirho = dag_with_chirho(
        &root_chirho,
        "save",
        vec![viewer_read_chirho(), viewer_write_chirho()],
    );
    crate::app_chirho::deploy_app_chirho(&root_chirho, APP_CHIRHO, home_dag_chirho, &owner_chirho)
        .unwrap();
    crate::app_chirho::deploy_app_route_chirho(
        &root_chirho,
        APP_CHIRHO,
        "view",
        view_dag_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    crate::app_chirho::deploy_app_route_chirho(
        &root_chirho,
        APP_CHIRHO,
        "save",
        save_dag_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    let client_chirho = register_client_chirho(&root_chirho, APP_CHIRHO, &owner_chirho).unwrap();
    LimitedFixtureChirho {
        root_chirho,
        owner_chirho,
        client_chirho,
        view_dag_chirho,
        save_dag_chirho,
    }
}

impl LimitedFixtureChirho {
    /// Open the view for page-read and the save for page-save, each over the page key.
    fn open_page_chirho(&self) {
        crate::app_chirho::append_app_key_authority_record_chirho(
            &self.root_chirho,
            APP_CHIRHO,
            &self.owner_chirho,
            self.page_openings_chirho(),
        )
        .unwrap();
    }

    /// The page's openings: the view for page-read and the save for page-save, each over the page key.
    fn page_openings_chirho(&self) -> Vec<AppKeyAuthorityRouteChirho> {
        vec![
            AppKeyAuthorityRouteChirho {
                route_chirho: "save".to_string(),
                action_chirho: "page-save-chirho".to_string(),
                dag_chirho: self.save_dag_chirho.clone(),
                resources_chirho: vec![PAGE_KEY_CHIRHO.to_string()],
            },
            AppKeyAuthorityRouteChirho {
                route_chirho: "view".to_string(),
                action_chirho: "page-read-chirho".to_string(),
                dag_chirho: self.view_dag_chirho.clone(),
                resources_chirho: vec![PAGE_KEY_CHIRHO.to_string()],
            },
        ]
    }

    fn user_chirho(&self, secret_chirho: &str) -> String {
        identity_chirho::register_identity_with_credential_chirho(
            &self.root_chirho,
            PrincipalKindChirho::UserChirho,
            secret_chirho,
        )
        .unwrap()
        .principal_chirho
    }

    fn limited_chirho(
        &self,
        principal_chirho: &str,
        secret_chirho: &str,
        actions_chirho: &[&str],
    ) -> ScopedTokenIssueChirho {
        issue_limited_key_chirho(
            &self.root_chirho,
            principal_chirho,
            secret_chirho,
            &self.client_chirho.client_id_chirho,
            &actions_chirho
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>(),
            None,
        )
        .unwrap()
    }

    fn legacy_chirho(
        &self,
        principal_chirho: &str,
        secret_chirho: &str,
        scopes_chirho: &[&str],
    ) -> Result<ScopedTokenIssueChirho> {
        issue_scoped_token_with_rate_limit_chirho(
            &self.root_chirho,
            principal_chirho,
            secret_chirho,
            &self.client_chirho.client_id_chirho,
            scopes_chirho.iter().map(|s| s.to_string()).collect(),
            Some(public_default_rate_limit_chirho()),
        )
    }
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
fn a_limited_key_is_invisible_to_the_plain_hash_lookup_older_engines_use_chirho() {
    let fixture_chirho = fixture_chirho("domain");
    fixture_chirho.open_page_chirho();
    let user_chirho = fixture_chirho.user_chirho("domain-user-secret");
    let key_chirho =
        fixture_chirho.limited_chirho(&user_chirho, "domain-user-secret", &["page-read-chirho"]);
    // Every engine before limited keys looks a bearer up by its plain blake3: it finds nothing.
    assert!(validate_scoped_token_for_app_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        &key_chirho.token_chirho
    )
    .unwrap()
    .is_none());
    assert_ne!(
        key_chirho.record_chirho.token_hash_chirho,
        token_hash_chirho(&key_chirho.token_chirho)
    );
    // This engine finds it, as a limited key with its grant set.
    assert!(matches!(
        resolve_bearer_for_app_chirho(
            &fixture_chirho.root_chirho,
            APP_CHIRHO,
            &key_chirho.token_chirho
        )
        .unwrap(),
        Some(BearerKeyChirho::LimitedChirho { .. })
    ));
    // And the whole token log still verifies under the full verifier, whose signed message is the old one.
    verify_scoped_tokens_chirho(&fixture_chirho.root_chirho).unwrap();
}

#[test]
fn a_limited_keys_signed_message_is_exactly_the_shape_older_engines_compute_chirho() {
    let fixture_chirho = fixture_chirho("message");
    fixture_chirho.open_page_chirho();
    let user_chirho = fixture_chirho.user_chirho("message-user-secret");
    let key_chirho =
        fixture_chirho.limited_chirho(&user_chirho, "message-user-secret", &["page-read-chirho"]);
    assert!(key_chirho.record_chirho.limited_grants_chirho.is_some());
    let message_chirho = scoped_token_message_chirho(&key_chirho.record_chirho).unwrap();
    let parsed_chirho: serde_json::Value = serde_json::from_slice(&message_chirho).unwrap();
    assert!(parsed_chirho.get("limited_grants_chirho").is_none());
    let mut stripped_chirho = key_chirho.record_chirho.clone();
    stripped_chirho.limited_grants_chirho = None;
    assert_eq!(
        message_chirho,
        scoped_token_message_chirho(&stripped_chirho).unwrap()
    );
    // The signed scopes carry the marker and the grant set's digest.
    assert!(key_chirho
        .record_chirho
        .scopes_chirho
        .iter()
        .any(|scope_chirho| scope_chirho == LIMITED_KEY_SCOPE_MARKER_CHIRHO));
}

#[test]
fn a_tampered_or_stripped_grant_set_refuses_and_never_falls_back_to_legacy_chirho() {
    for (label_chirho, edit_chirho) in [
        (
            "widened",
            Box::new(|value_chirho: &mut serde_json::Value| {
                value_chirho["limited_grants_chirho"]["actions_chirho"][0]["resources_chirho"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::Value::from("figures-chirho"));
            }) as Box<dyn FnOnce(&mut serde_json::Value)>,
        ),
        (
            "stripped",
            Box::new(|value_chirho: &mut serde_json::Value| {
                value_chirho
                    .as_object_mut()
                    .unwrap()
                    .remove("limited_grants_chirho");
            }),
        ),
    ] {
        let fixture_chirho = fixture_chirho(label_chirho);
        fixture_chirho.open_page_chirho();
        let user_chirho = fixture_chirho.user_chirho("tamper-user-secret");
        let key_chirho = fixture_chirho.limited_chirho(
            &user_chirho,
            "tamper-user-secret",
            &["page-read-chirho"],
        );
        edit_last_token_line_chirho(&fixture_chirho.root_chirho, edit_chirho);
        let refused_chirho = resolve_bearer_for_app_chirho(
            &fixture_chirho.root_chirho,
            APP_CHIRHO,
            &key_chirho.token_chirho,
        );
        assert!(
            refused_chirho.is_err(),
            "{label_chirho}: {refused_chirho:?}"
        );
    }
}

#[test]
fn a_plain_hash_key_claiming_limited_status_is_refused_chirho() {
    let fixture_chirho = fixture_chirho("claim");
    let user_chirho = fixture_chirho.user_chirho("claim-user-secret");
    // Free-text scopes let a legacy issuance write the marker; it buys nothing but a refusal.
    let forged_chirho = fixture_chirho
        .legacy_chirho(
            &user_chirho,
            "claim-user-secret",
            &[LIMITED_KEY_SCOPE_MARKER_CHIRHO],
        )
        .unwrap();
    assert!(resolve_bearer_for_app_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        &forged_chirho.token_chirho
    )
    .is_err());
}

#[test]
fn the_key_authority_log_is_sticky_and_a_tampered_record_fails_closed_chirho() {
    let sticky_chirho = fixture_chirho("sticky");
    assert!(crate::app_chirho::app_key_authority_record_chirho(
        &sticky_chirho.root_chirho,
        APP_CHIRHO
    )
    .unwrap()
    .is_none());
    sticky_chirho.open_page_chirho();
    // A later record that opens nothing keeps the app limited: there is still a record.
    crate::app_chirho::append_app_key_authority_record_chirho(
        &sticky_chirho.root_chirho,
        APP_CHIRHO,
        &sticky_chirho.owner_chirho,
        Vec::new(),
    )
    .unwrap();
    let latest_chirho =
        crate::app_chirho::app_key_authority_record_chirho(&sticky_chirho.root_chirho, APP_CHIRHO)
            .unwrap()
            .expect("still limited");
    assert!(latest_chirho.routes_chirho.is_empty());

    // A changed byte in a record the view has not folded yet: the read refuses, it does not answer "legacy".
    let fresh_chirho = fixture_chirho("tamper-authority");
    fresh_chirho.open_page_chirho();
    let path_chirho =
        crate::app_chirho::app_key_authority_records_path_chirho(&fresh_chirho.root_chirho);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    std::fs::write(
        &path_chirho,
        text_chirho.replace("page-read-chirho", "page-rexd-chirho"),
    )
    .unwrap();
    assert!(crate::app_chirho::app_key_authority_record_chirho(
        &fresh_chirho.root_chirho,
        APP_CHIRHO
    )
    .is_err());
}

#[test]
fn an_opening_is_bound_to_the_dag_it_was_reviewed_with_chirho() {
    let fixture_chirho = fixture_chirho("bound");
    fixture_chirho.open_page_chirho();
    let user_chirho = fixture_chirho.user_chirho("bound-user-secret");
    let key_chirho =
        fixture_chirho.limited_chirho(&user_chirho, "bound-user-secret", &["page-read-chirho"]);
    let admitted_chirho = admit_bearer_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        KeyEntryChirho::NamedRouteChirho("view"),
        &key_chirho.token_chirho,
    )
    .unwrap();
    assert!(matches!(
        admitted_chirho,
        Some(KeyAdmissionChirho::LimitedChirho { .. })
    ));
    // The view is redeployed onto another DAG with the very same capability, and nobody opened it again.
    let other_view_chirho = dag_with_chirho(
        &fixture_chirho.root_chirho,
        "view-two",
        vec![viewer_read_chirho()],
    );
    crate::app_chirho::deploy_app_route_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        "view",
        other_view_chirho,
        &fixture_chirho.owner_chirho,
    )
    .unwrap();
    let refusal_chirho = admit_bearer_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        KeyEntryChirho::NamedRouteChirho("view"),
        &key_chirho.token_chirho,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho.downcast_ref::<KeyRouteRefusalChirho>(),
        Some(&KeyRouteRefusalChirho::RouteNotOpenChirho)
    );
}

#[test]
fn every_entry_but_an_opened_route_refuses_each_kind_of_key_for_its_mode_chirho() {
    let fixture_chirho = fixture_chirho("modes");
    let user_chirho = fixture_chirho.user_chirho("modes-user-secret");
    let legacy_chirho = fixture_chirho
        .legacy_chirho(&user_chirho, "modes-user-secret", &[])
        .unwrap();
    // Legacy mode: a legacy key keeps today's meaning everywhere.
    for entry_chirho in [
        KeyEntryChirho::OtherEntryChirho,
        KeyEntryChirho::NamedRouteChirho("save"),
    ] {
        assert!(matches!(
            admit_bearer_chirho(
                &fixture_chirho.root_chirho,
                APP_CHIRHO,
                entry_chirho,
                &legacy_chirho.token_chirho
            )
            .unwrap(),
            Some(KeyAdmissionChirho::LegacyChirho(_))
        ));
    }
    fixture_chirho.open_page_chirho();
    // Limited mode: a limited key on any other entry, and a legacy key anywhere, refuse.
    let limited_chirho =
        fixture_chirho.limited_chirho(&user_chirho, "modes-user-secret", &["page-read-chirho"]);
    let refusal_chirho = admit_bearer_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        KeyEntryChirho::OtherEntryChirho,
        &limited_chirho.token_chirho,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho.downcast_ref::<KeyRouteRefusalChirho>(),
        Some(&KeyRouteRefusalChirho::RouteNotOpenChirho)
    );
    // The legacy key was never retired here (the record was appended with no deploy to retire it), as a key an older
    // engine minted during a rollback would be: it refuses on every entry, the opened routes included.
    for entry_chirho in [
        KeyEntryChirho::OtherEntryChirho,
        KeyEntryChirho::NamedRouteChirho("view"),
        KeyEntryChirho::NamedRouteChirho("save"),
    ] {
        let refusal_chirho = admit_bearer_chirho(
            &fixture_chirho.root_chirho,
            APP_CHIRHO,
            entry_chirho,
            &legacy_chirho.token_chirho,
        )
        .unwrap_err();
        assert_eq!(
            refusal_chirho.downcast_ref::<KeyRouteRefusalChirho>(),
            Some(&KeyRouteRefusalChirho::RouteNotOpenChirho)
        );
    }
}

#[test]
fn retirement_ends_exactly_the_apps_legacy_keys_and_repeats_as_a_no_op_chirho() {
    let fixture_chirho = fixture_chirho("retire");
    let first_chirho = fixture_chirho.user_chirho("retire-first-secret");
    let second_chirho = fixture_chirho.user_chirho("retire-second-secret");
    let first_key_chirho = fixture_chirho
        .legacy_chirho(&first_chirho, "retire-first-secret", &[])
        .unwrap();
    let second_key_chirho = fixture_chirho
        .legacy_chirho(&second_chirho, "retire-second-secret", &[])
        .unwrap();
    // Another app's legacy key, which retirement must not touch.
    let other_owner_chirho = identity_chirho::register_identity_chirho(
        &fixture_chirho.root_chirho,
        PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let other_client_chirho =
        register_client_chirho(&fixture_chirho.root_chirho, "other", &other_owner_chirho).unwrap();
    let other_key_chirho = issue_scoped_token_with_rate_limit_chirho(
        &fixture_chirho.root_chirho,
        &first_chirho,
        "retire-first-secret",
        &other_client_chirho.client_id_chirho,
        Vec::new(),
        Some(public_default_rate_limit_chirho()),
    )
    .unwrap();

    assert_eq!(
        retire_legacy_keys_for_app_chirho(&fixture_chirho.root_chirho, APP_CHIRHO).unwrap(),
        2
    );
    for key_chirho in [&first_key_chirho, &second_key_chirho] {
        assert!(validate_scoped_token_for_app_chirho(
            &fixture_chirho.root_chirho,
            APP_CHIRHO,
            &key_chirho.token_chirho
        )
        .unwrap()
        .is_none());
    }
    assert!(validate_scoped_token_for_app_chirho(
        &fixture_chirho.root_chirho,
        "other",
        &other_key_chirho.token_chirho
    )
    .unwrap()
    .is_some());
    // A limited key issued afterwards is not a legacy key: a repeat retires nothing.
    fixture_chirho.open_page_chirho();
    let limited_chirho =
        fixture_chirho.limited_chirho(&first_chirho, "retire-first-secret", &["page-read-chirho"]);
    assert_eq!(
        retire_legacy_keys_for_app_chirho(&fixture_chirho.root_chirho, APP_CHIRHO).unwrap(),
        0
    );
    assert!(resolve_bearer_for_app_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        &limited_chirho.token_chirho
    )
    .unwrap()
    .is_some());
}

#[test]
fn a_limited_keys_run_is_never_resumed_without_its_limit_chirho() {
    let fixture_chirho = fixture_chirho("resume");
    fixture_chirho.open_page_chirho();
    let user_chirho = fixture_chirho.user_chirho("resume-user-secret");
    let key_chirho =
        fixture_chirho.limited_chirho(&user_chirho, "resume-user-secret", &["page-read-chirho"]);
    let scope_chirho = crate::effect_chirho::run_intent_chirho::RunIntentScopeChirho {
        kind_chirho: "app-run-chirho".to_string(),
        app_hash_chirho: None,
        user_principal_hash_chirho: None,
        owner_principal_hash_chirho: None,
        client_id_hash_chirho: None,
        token_hash_chirho: Some(key_chirho.record_chirho.token_hash_chirho.clone()),
        price_book_chirho: None,
        billing_policy_chirho: None,
    };
    let refusal_chirho = crate::effect_chirho::run_intent_chirho::resume_request_context_chirho(
        &fixture_chirho.root_chirho,
        &scope_chirho,
    )
    .unwrap_err();
    assert!(
        format!("{refusal_chirho:#}").contains("limited key's run is not resumed"),
        "{refusal_chirho:#}"
    );
}

#[test]
fn the_key_authority_view_folds_only_what_was_appended_chirho() {
    let fixture_chirho = fixture_chirho("growth");
    fixture_chirho.open_page_chirho();
    let read_chirho = || {
        crate::app_chirho::app_key_authority_record_chirho(&fixture_chirho.root_chirho, APP_CHIRHO)
            .unwrap()
            .unwrap()
    };
    read_chirho();
    // Warm: a read folds nothing.
    let before_chirho = crate::app_chirho::key_authority_folds_chirho();
    read_chirho();
    assert_eq!(
        crate::app_chirho::key_authority_folds_chirho(),
        before_chirho
    );
    // An unrelated app appends twenty records: the next read folds exactly those, once, and the read after folds none.
    let other_owner_chirho = fixture_chirho.owner_chirho.clone();
    let other_dag_chirho = dag_with_chirho(
        &fixture_chirho.root_chirho,
        "other-home",
        vec![viewer_read_chirho()],
    );
    crate::app_chirho::deploy_app_chirho(
        &fixture_chirho.root_chirho,
        "unrelated",
        other_dag_chirho,
        &other_owner_chirho,
    )
    .unwrap();
    for _ in 0..20 {
        crate::app_chirho::append_app_key_authority_record_chirho(
            &fixture_chirho.root_chirho,
            "unrelated",
            &other_owner_chirho,
            Vec::new(),
        )
        .unwrap();
    }
    let before_chirho = crate::app_chirho::key_authority_folds_chirho();
    read_chirho();
    assert_eq!(
        crate::app_chirho::key_authority_folds_chirho(),
        before_chirho + 20
    );
    read_chirho();
    assert_eq!(
        crate::app_chirho::key_authority_folds_chirho(),
        before_chirho + 20
    );
}

#[test]
fn a_legacy_issuance_that_signed_in_before_the_app_opened_is_refused_at_its_append_chirho() {
    let fixture_chirho = fixture_chirho("race-after");
    let user_chirho = fixture_chirho.user_chirho("race-after-secret");
    // The issuance's first half, while the app opens nothing: its check passes and the credential is proved.
    refuse_legacy_key_for_limited_app_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.client_chirho,
    )
    .unwrap();
    let login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &fixture_chirho.root_chirho,
        &user_chirho,
        "race-after-secret",
    )
    .unwrap();
    // The app opens a route before the issuance appends.
    fixture_chirho.open_page_chirho();
    let tokens_path_chirho = scoped_tokens_path_chirho(&fixture_chirho.root_chirho);
    let tokens_before_chirho = std::fs::read(&tokens_path_chirho).unwrap_or_default();
    // The second half re-checks under the append lock and refuses; nothing is appended.
    let refusal_chirho = issue_scoped_token_after_login_at_chirho(
        &fixture_chirho.root_chirho,
        fixture_chirho.client_chirho.clone(),
        login_chirho,
        IssuedKeyKindChirho::LegacyChirho(Vec::new()),
        Some(public_default_rate_limit_chirho()),
        now_ms_chirho,
    )
    .unwrap_err();
    assert!(
        refusal_chirho
            .downcast_ref::<LegacyKeyForLimitedAppChirho>()
            .is_some(),
        "{refusal_chirho:#}"
    );
    assert_eq!(
        std::fs::read(&tokens_path_chirho).unwrap_or_default(),
        tokens_before_chirho
    );
}

#[test]
fn a_legacy_append_racing_the_opt_in_waits_for_its_locked_section_and_is_refused_chirho() {
    let fixture_chirho = fixture_chirho("race-section");
    let user_chirho = fixture_chirho.user_chirho("race-section-secret");
    // The racing issuance's first half, while the app opens nothing: its check passes and the credential is proved.
    refuse_legacy_key_for_limited_app_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.client_chirho,
    )
    .unwrap();
    let login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &fixture_chirho.root_chirho,
        &user_chirho,
        "race-section-secret",
    )
    .unwrap();
    let (go_tx_chirho, go_rx_chirho) = std::sync::mpsc::channel::<()>();
    let (attempting_tx_chirho, attempting_rx_chirho) = std::sync::mpsc::channel::<()>();
    let root_for_issuer_chirho = fixture_chirho.root_chirho.clone();
    let client_for_issuer_chirho = fixture_chirho.client_chirho.clone();
    let issuer_chirho = std::thread::spawn(move || {
        go_rx_chirho.recv().unwrap();
        attempting_tx_chirho.send(()).unwrap();
        // Its second half, the locked append, attempted while the opt-in's section holds the lock.
        issue_scoped_token_after_login_at_chirho(
            &root_for_issuer_chirho,
            client_for_issuer_chirho,
            login_chirho,
            IssuedKeyKindChirho::LegacyChirho(Vec::new()),
            Some(public_default_rate_limit_chirho()),
            now_ms_chirho,
        )
    });
    // Inside the section, after its retirements and before its record, the racing append is let go and given time to
    // meet the lock. If the lock did not span the section, the append would land here, unretired.
    crate::app_manifest_chirho::set_opt_in_hold_chirho(move || {
        go_tx_chirho.send(()).unwrap();
        attempting_rx_chirho.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(250));
        Ok(())
    });
    crate::oauth_chirho::with_k1_era_opening_chirho(|| {
        // A K1-era root: the fixture's legacy client predates the opening, which K4 refuses outside this seam.
        crate::app_manifest_chirho::open_app_to_limited_keys_chirho(
            &fixture_chirho.root_chirho,
            APP_CHIRHO,
            &fixture_chirho.owner_chirho,
            fixture_chirho.page_openings_chirho(),
        )
    })
    .unwrap();
    // It waited for the section, then its re-check under the same lock met the opening.
    let refusal_chirho = issuer_chirho.join().unwrap().unwrap_err();
    assert!(
        refusal_chirho
            .downcast_ref::<LegacyKeyForLimitedAppChirho>()
            .is_some(),
        "{refusal_chirho:#}"
    );
}

#[test]
fn an_interrupted_opt_in_leaves_retired_keys_and_no_opening_and_says_so_chirho() {
    let fixture_chirho = fixture_chirho("interrupted");
    let user_chirho = fixture_chirho.user_chirho("interrupted-secret");
    let key_chirho = fixture_chirho
        .legacy_chirho(&user_chirho, "interrupted-secret", &[])
        .unwrap();
    // The process stops inside the section, after its retirements and before its record.
    crate::app_manifest_chirho::set_opt_in_hold_chirho(|| anyhow::bail!("the process stops here"));
    let failure_chirho = crate::oauth_chirho::with_k1_era_opening_chirho(|| {
        // A K1-era root: the fixture's legacy client predates the opening, which K4 refuses outside this seam.
        crate::app_manifest_chirho::open_app_to_limited_keys_chirho(
            &fixture_chirho.root_chirho,
            APP_CHIRHO,
            &fixture_chirho.owner_chirho,
            fixture_chirho.page_openings_chirho(),
        )
    })
    .unwrap_err();
    // The failure says the root changed; it never reads as untouched.
    let text_chirho = format!("{failure_chirho:#}");
    assert!(
        text_chirho.contains(
            "1 legacy key(s) of 'keyed' were retired, but its opening to limited keys was not recorded"
        ),
        "{text_chirho}"
    );
    // No opening is on disk, and the key is retired, which every engine down to the rollback floor honours: nothing
    // here is a legacy key live beside an opening.
    assert!(crate::app_chirho::app_key_authority_record_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO
    )
    .unwrap()
    .is_none());
    assert!(validate_scoped_token_for_app_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        &key_chirho.token_chirho
    )
    .unwrap()
    .is_none());
    // Deploying again finishes the opt-in.
    crate::oauth_chirho::with_k1_era_opening_chirho(|| {
        // A K1-era root: the fixture's legacy client predates the opening, which K4 refuses outside this seam.
        crate::app_manifest_chirho::open_app_to_limited_keys_chirho(
            &fixture_chirho.root_chirho,
            APP_CHIRHO,
            &fixture_chirho.owner_chirho,
            fixture_chirho.page_openings_chirho(),
        )
    })
    .unwrap();
    assert!(crate::app_chirho::app_key_authority_record_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO
    )
    .unwrap()
    .is_some());
}

#[test]
fn an_authority_log_that_cannot_be_examined_is_an_error_never_legacy_mode_chirho() {
    // The legacy control: a log that does not exist is the legacy era, and a legacy key is admitted.
    let fixture_chirho = fixture_chirho("metadata");
    let root_chirho = &fixture_chirho.root_chirho;
    assert!(
        crate::app_chirho::app_key_authority_record_chirho(root_chirho, APP_CHIRHO)
            .unwrap()
            .is_none()
    );
    let user_chirho = fixture_chirho.user_chirho("metadata-secret");
    let legacy_chirho = fixture_chirho
        .legacy_chirho(&user_chirho, "metadata-secret", &[])
        .unwrap();
    assert!(matches!(
        admit_bearer_chirho(
            root_chirho,
            APP_CHIRHO,
            KeyEntryChirho::NamedRouteChirho("view"),
            &legacy_chirho.token_chirho
        )
        .unwrap(),
        Some(KeyAdmissionChirho::LegacyChirho(_))
    ));
    // Not a regular file: a symlink looping onto itself where the log belongs.
    let path_chirho = crate::app_chirho::app_key_authority_records_path_chirho(root_chirho);
    std::os::unix::fs::symlink(&path_chirho, &path_chirho).unwrap();
    assert!(crate::app_chirho::app_key_authority_record_chirho(root_chirho, APP_CHIRHO).is_err());
    assert!(crate::app_chirho::load_app_key_authority_records_chirho(root_chirho).is_err());
    // A bearer is refused, never admitted as in the legacy era, and no legacy key is issued.
    assert!(admit_bearer_chirho(
        root_chirho,
        APP_CHIRHO,
        KeyEntryChirho::NamedRouteChirho("view"),
        &legacy_chirho.token_chirho
    )
    .is_err());
    assert!(fixture_chirho
        .legacy_chirho(&user_chirho, "metadata-secret", &[])
        .is_err());
    // A directory where the log belongs.
    std::fs::remove_file(&path_chirho).unwrap();
    std::fs::create_dir(&path_chirho).unwrap();
    assert!(crate::app_chirho::app_key_authority_record_chirho(root_chirho, APP_CHIRHO).is_err());
    std::fs::remove_dir(&path_chirho).unwrap();
    // A symlink to a real, verifiable log elsewhere: reading through it would succeed, so only the regular-file rule
    // refuses it. The log is never followed somewhere else.
    let elsewhere_chirho = self::fixture_chirho("metadata-elsewhere");
    elsewhere_chirho.open_page_chirho();
    std::os::unix::fs::symlink(
        crate::app_chirho::app_key_authority_records_path_chirho(&elsewhere_chirho.root_chirho),
        &path_chirho,
    )
    .unwrap();
    assert!(crate::app_chirho::app_key_authority_record_chirho(root_chirho, APP_CHIRHO).is_err());
    std::fs::remove_file(&path_chirho).unwrap();
    // A metadata error: a root reached through a symlink loop, where the filesystem cannot say whether the log exists.
    let looped_dir_chirho = tmp_root_chirho("metadata-loop");
    let looped_chirho = looped_dir_chirho.join("loop-chirho");
    std::os::unix::fs::symlink(&looped_chirho, &looped_chirho).unwrap();
    let error_chirho =
        crate::app_chirho::app_key_authority_record_chirho(&looped_chirho, APP_CHIRHO).unwrap_err();
    // The shared rule refuses it by its own error: the loop the filesystem reported, never an absence.
    assert!(
        error_chirho.chain().any(|cause_chirho| cause_chirho
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_chirho| io_chirho.raw_os_error() == Some(libc::ELOOP))),
        "{error_chirho:#}"
    );
    assert!(crate::app_chirho::load_app_key_authority_records_chirho(&looped_chirho).is_err());
}

#[test]
fn a_limited_key_ends_at_its_expiry_and_when_its_owner_revokes_it_chirho() {
    let fixture_chirho = fixture_chirho("ends");
    fixture_chirho.open_page_chirho();
    let user_chirho = fixture_chirho.user_chirho("ends-user-secret");
    let first_chirho =
        fixture_chirho.limited_chirho(&user_chirho, "ends-user-secret", &["page-read-chirho"]);
    let second_chirho =
        fixture_chirho.limited_chirho(&user_chirho, "ends-user-secret", &["page-read-chirho"]);
    let resolve_at_chirho = |token_chirho: &str, now_chirho: u64| {
        super::limited_key_chirho::resolve_bearer_for_app_at_chirho(
            &fixture_chirho.root_chirho,
            APP_CHIRHO,
            token_chirho,
            now_chirho,
        )
        .unwrap()
    };
    // Expiry: live just before, no key just after (an ended limited key never falls back to anything).
    let expires_chirho = first_chirho.record_chirho.expires_ms_chirho;
    assert!(matches!(
        resolve_at_chirho(&first_chirho.token_chirho, expires_chirho - 1),
        Some(BearerKeyChirho::LimitedChirho { .. })
    ));
    assert!(resolve_at_chirho(&first_chirho.token_chirho, expires_chirho + 1).is_none());
    // Revocation by the owner's key id ends exactly that key, and the bearer door refuses it as no key.
    revoke_own_key_chirho(
        &fixture_chirho.root_chirho,
        &user_chirho,
        &scoped_key_id_chirho(&first_chirho.record_chirho.token_hash_chirho),
    )
    .unwrap();
    let now_chirho = now_ms_chirho();
    assert!(resolve_at_chirho(&first_chirho.token_chirho, now_chirho).is_none());
    assert!(matches!(
        resolve_at_chirho(&second_chirho.token_chirho, now_chirho),
        Some(BearerKeyChirho::LimitedChirho { .. })
    ));
    assert!(admit_bearer_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        KeyEntryChirho::NamedRouteChirho("view"),
        &first_chirho.token_chirho,
    )
    .unwrap()
    .is_none());
}

#[test]
fn the_compliance_verifier_reads_the_whole_key_authority_log_and_refuses_a_tampered_record_chirho()
{
    let fixture_chirho = fixture_chirho("compliance");
    let verify_chirho =
        || crate::app_chirho::verify_app_key_authority_records_chirho(&fixture_chirho.root_chirho);
    assert_eq!(verify_chirho().unwrap(), 0);
    fixture_chirho.open_page_chirho();
    fixture_chirho.open_page_chirho();
    assert_eq!(verify_chirho().unwrap(), 2);
    let path_chirho =
        crate::app_chirho::app_key_authority_records_path_chirho(&fixture_chirho.root_chirho);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    std::fs::write(
        &path_chirho,
        text_chirho.replacen("page-save-chirho", "page-sxve-chirho", 1),
    )
    .unwrap();
    assert!(verify_chirho().is_err());
}
