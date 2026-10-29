// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;

fn strings_chirho(values_chirho: &[&str]) -> Vec<String> {
    values_chirho
        .iter()
        .map(|value_chirho| value_chirho.to_string())
        .collect()
}

fn viewer_read_chirho() -> CapabilityChirho {
    CapabilityChirho::ReadStoreChirho {
        prefix_chirho: VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO.to_string(),
    }
}

fn viewer_write_chirho() -> CapabilityChirho {
    CapabilityChirho::WriteStoreChirho {
        prefix_chirho: VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO.to_string(),
    }
}

/// One capability of every variant, each with the class the law must give it. A variant missing here is caught by the
/// exhaustive match in the law itself; this table pins each answer.
fn every_variant_chirho() -> Vec<(CapabilityChirho, KeyActionClassChirho)> {
    use KeyActionClassChirho::{NeverChirho, ReadChirho, WriteChirho};
    vec![
        (viewer_read_chirho(), ReadChirho),
        (viewer_write_chirho(), WriteChirho),
        (
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "rows-chirho/".to_string(),
            },
            NeverChirho,
        ),
        (
            CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "rows-chirho/".to_string(),
            },
            NeverChirho,
        ),
        (
            CapabilityChirho::PaidEffectChirho {
                effect_chirho: "llm-chirho".to_string(),
                caller_chirho: "caller-chirho".to_string(),
            },
            NeverChirho,
        ),
        (
            CapabilityChirho::UserIdentityChirho {
                principal_chirho: "user/a".to_string(),
                client_id_chirho: "client/a".to_string(),
                token_hash_chirho: "hash".to_string(),
            },
            ReadChirho,
        ),
        (
            CapabilityChirho::AppContextChirho {
                app_chirho: "app".to_string(),
                owner_principal_chirho: "owner/a".to_string(),
                price_book_chirho: None,
                billing_policy_chirho: None,
            },
            ReadChirho,
        ),
        (
            CapabilityChirho::SecretRefChirho {
                name_chirho: "secret".to_string(),
            },
            NeverChirho,
        ),
        (
            CapabilityChirho::RealtimeSessionChirho {
                app_chirho: "app".to_string(),
                caller_chirho: "caller".to_string(),
            },
            NeverChirho,
        ),
        (
            CapabilityChirho::SupportIssueChirho {
                issue_chirho: "issue".to_string(),
                actions_chirho: Vec::new(),
            },
            NeverChirho,
        ),
        (
            CapabilityChirho::CausalReversionChirho {
                branch_chirho: "main".to_string(),
            },
            NeverChirho,
        ),
        (
            CapabilityChirho::NetChirho {
                allowlist_chirho: vec!["example.com".to_string()],
            },
            NeverChirho,
        ),
        (
            CapabilityChirho::QueryChirho {
                prefix_chirho: "rows-chirho/".to_string(),
                caller_chirho: "caller".to_string(),
                max_rows_chirho: 10,
            },
            NeverChirho,
        ),
        (CapabilityChirho::ClockChirho, ReadChirho),
        (CapabilityChirho::RandomChirho, ReadChirho),
        (
            CapabilityChirho::InvokeChirho {
                node_chirho: HashChirho("00".repeat(32)),
            },
            NeverChirho,
        ),
        (
            CapabilityChirho::TemplateAppDeployChirho {
                template_id_chirho: "page-template-chirho".to_string(),
            },
            NeverChirho,
        ),
    ]
}

/// One refusal case: the key's grant set, the route, the action the route is opened for, the route's capabilities, and
/// the refusal expected.
type RefusalCaseChirho<'a> = (
    &'a LimitedKeyGrantsChirho,
    &'a str,
    Option<&'a str>,
    &'a [CapabilityChirho],
    KeyRouteRefusalChirho,
);

#[test]
fn every_capability_variant_has_its_pinned_class_chirho() {
    for (capability_chirho, expected_chirho) in every_variant_chirho() {
        assert_eq!(
            capability_key_action_class_chirho(&capability_chirho),
            expected_chirho,
            "{capability_chirho:?}"
        );
    }
}

#[test]
fn only_the_exact_viewer_state_prefix_is_a_reachable_store_chirho() {
    // The reserved roads and every near spelling of viewer-state are out of reach: only the one prefix whose logical
    // keys the door can bound is eligible.
    for prefix_chirho in [
        OWN_KEYS_CAPABILITY_PREFIX_CHIRHO,
        "own-keys-chirho",
        "publication-chirho/",
        "viewer-state-chirho",
        "viewer-state-chirho/page/",
        "viewer-state-chirhox/",
        "",
    ] {
        for capability_chirho in [
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: prefix_chirho.to_string(),
            },
            CapabilityChirho::WriteStoreChirho {
                prefix_chirho: prefix_chirho.to_string(),
            },
        ] {
            assert_eq!(
                capability_key_action_class_chirho(&capability_chirho),
                KeyActionClassChirho::NeverChirho,
                "{capability_chirho:?}"
            );
        }
    }
}

#[test]
fn a_dag_takes_its_highest_class_and_a_pure_dag_reads_chirho() {
    let publish_chirho = CapabilityChirho::TemplateAppDeployChirho {
        template_id_chirho: "page-template-chirho".to_string(),
    };
    assert_eq!(
        dag_key_action_class_chirho(std::iter::empty()),
        KeyActionClassChirho::ReadChirho
    );
    assert_eq!(
        dag_key_action_class_chirho([&viewer_read_chirho(), &viewer_write_chirho()]),
        KeyActionClassChirho::WriteChirho
    );
    assert_eq!(
        dag_key_action_class_chirho([&viewer_write_chirho(), &viewer_read_chirho()]),
        KeyActionClassChirho::WriteChirho
    );
    assert_eq!(
        dag_key_action_class_chirho([&viewer_read_chirho(), &publish_chirho]),
        KeyActionClassChirho::NeverChirho
    );
}

fn page_routes_chirho() -> Vec<OpenedKeyRouteChirho> {
    vec![
        OpenedKeyRouteChirho {
            route_chirho: "agent-page-chirho".to_string(),
            action_chirho: "page-read-chirho".to_string(),
            capabilities_chirho: vec![viewer_read_chirho()],
            resources_chirho: strings_chirho(&["page-document-chirho"]),
        },
        OpenedKeyRouteChirho {
            route_chirho: "preview-chirho".to_string(),
            action_chirho: "page-preview-chirho".to_string(),
            capabilities_chirho: vec![viewer_read_chirho()],
            resources_chirho: strings_chirho(&["page-document-chirho"]),
        },
        OpenedKeyRouteChirho {
            route_chirho: "agent-save-page-chirho".to_string(),
            action_chirho: "page-save-chirho".to_string(),
            capabilities_chirho: vec![viewer_read_chirho(), viewer_write_chirho()],
            resources_chirho: strings_chirho(&["page-document-chirho"]),
        },
    ]
}

fn grants_chirho(actions_chirho: &[&str]) -> LimitedKeyGrantsChirho {
    limited_key_grants_for_actions_chirho(
        "perffection-workspace",
        &strings_chirho(actions_chirho),
        &page_routes_chirho(),
    )
    .expect("the grant set builds")
}

#[test]
fn a_grant_set_names_its_routes_authority_and_resources_sorted_chirho() {
    let grants_chirho = grants_chirho(&["page-save-chirho", "page-read-chirho"]);
    assert_eq!(
        grants_chirho.schema_chirho,
        LIMITED_KEY_GRANTS_SCHEMA_CHIRHO
    );
    assert_eq!(grants_chirho.app_chirho, "perffection-workspace");
    let actions_chirho: Vec<&str> = grants_chirho
        .actions_chirho
        .iter()
        .map(|grant_chirho| grant_chirho.action_chirho.as_str())
        .collect();
    assert_eq!(actions_chirho, ["page-read-chirho", "page-save-chirho"]);
    let save_chirho = &grants_chirho.actions_chirho[1];
    assert_eq!(save_chirho.routes_chirho, ["agent-save-page-chirho"]);
    assert_eq!(
        save_chirho.authority_chirho,
        [viewer_read_chirho(), viewer_write_chirho()]
    );
    assert_eq!(save_chirho.resources_chirho, ["page-document-chirho"]);
}

#[test]
fn issuance_refuses_what_no_opened_route_declares_repeats_and_empty_sets_chirho() {
    let routes_chirho = page_routes_chirho();
    for (requested_chirho, expected_chirho) in [
        (vec![], "at least one action"),
        (
            vec!["figures-read-chirho"],
            "declares the action 'figures-read-chirho'",
        ),
        (
            vec!["page-read-chirho", "page-read-chirho"],
            "must not repeat",
        ),
    ] {
        let error_chirho = limited_key_grants_for_actions_chirho(
            "perffection-workspace",
            &strings_chirho(&requested_chirho),
            &routes_chirho,
        )
        .expect_err("refused")
        .to_string();
        assert!(error_chirho.contains(expected_chirho), "{error_chirho}");
    }
    // A route holding a capability no key may reach cannot be granted, even if it was opened.
    let mut publishing_chirho = page_routes_chirho();
    publishing_chirho[2]
        .capabilities_chirho
        .push(CapabilityChirho::TemplateAppDeployChirho {
            template_id_chirho: "page-template-chirho".to_string(),
        });
    assert!(limited_key_grants_for_actions_chirho(
        "perffection-workspace",
        &strings_chirho(&["page-save-chirho"]),
        &publishing_chirho,
    )
    .is_err());
}

#[test]
fn signed_scopes_bind_the_grant_set_and_a_changed_set_refuses_chirho() {
    let grants_chirho = grants_chirho(&["page-read-chirho"]);
    let scopes_chirho = limited_key_scopes_chirho(&grants_chirho).expect("scopes");
    assert!(scopes_mark_limited_key_chirho(&scopes_chirho));
    verify_limited_key_grants_chirho(&scopes_chirho, "perffection-workspace", &grants_chirho)
        .expect("the bound set verifies");
    // Widening the set after signing breaks the binding.
    let mut widened_chirho = grants_chirho.clone();
    widened_chirho.actions_chirho[0]
        .resources_chirho
        .push("figures-chirho".to_string());
    assert!(verify_limited_key_grants_chirho(
        &scopes_chirho,
        "perffection-workspace",
        &widened_chirho
    )
    .is_err());
    // Another app, a missing marker, a missing digest and a second digest all refuse.
    assert!(verify_limited_key_grants_chirho(&scopes_chirho, "other-app", &grants_chirho).is_err());
    let unmarked_chirho: Vec<String> = scopes_chirho
        .iter()
        .filter(|scope_chirho| scope_chirho.as_str() != LIMITED_KEY_SCOPE_MARKER_CHIRHO)
        .cloned()
        .collect();
    assert!(verify_limited_key_grants_chirho(
        &unmarked_chirho,
        "perffection-workspace",
        &grants_chirho
    )
    .is_err());
    assert!(verify_limited_key_grants_chirho(
        &strings_chirho(&[LIMITED_KEY_SCOPE_MARKER_CHIRHO]),
        "perffection-workspace",
        &grants_chirho
    )
    .is_err());
    let mut doubled_chirho = scopes_chirho.clone();
    doubled_chirho.push(format!(
        "{LIMITED_KEY_GRANTS_DIGEST_SCOPE_PREFIX_CHIRHO}{}",
        "0".repeat(64)
    ));
    assert!(verify_limited_key_grants_chirho(
        &doubled_chirho,
        "perffection-workspace",
        &grants_chirho
    )
    .is_err());
}

#[test]
fn the_route_decision_matrix_chirho() {
    use KeyRouteRefusalChirho::{
        ActionNotGrantedChirho, AuthorityChangedChirho, RouteNotOpenChirho,
    };
    let read_only_chirho = grants_chirho(&["page-preview-chirho", "page-read-chirho"]);
    let with_save_chirho = grants_chirho(&[
        "page-preview-chirho",
        "page-read-chirho",
        "page-save-chirho",
    ]);
    let read_caps_chirho = [viewer_read_chirho()];
    let save_caps_chirho = [viewer_read_chirho(), viewer_write_chirho()];
    let publishing_caps_chirho = [
        viewer_write_chirho(),
        CapabilityChirho::TemplateAppDeployChirho {
            template_id_chirho: "t".to_string(),
        },
    ];

    // Allowed, with the grant's limit returned.
    let limit_chirho = limited_key_route_decision_chirho(
        &read_only_chirho,
        "agent-page-chirho",
        Some("page-read-chirho"),
        &read_caps_chirho,
    )
    .expect("a read key reads");
    assert_eq!(limit_chirho.action_chirho, "page-read-chirho");
    assert_eq!(limit_chirho.resources_chirho, ["page-document-chirho"]);
    assert!(limited_key_route_decision_chirho(
        &with_save_chirho,
        "agent-save-page-chirho",
        Some("page-save-chirho"),
        &save_caps_chirho,
    )
    .is_ok());

    let cases_chirho: Vec<RefusalCaseChirho<'_>> = vec![
        // A read key cannot save.
        (
            &read_only_chirho,
            "agent-save-page-chirho",
            Some("page-save-chirho"),
            &save_caps_chirho,
            ActionNotGrantedChirho,
        ),
        // An unopened route, or one whose DAG is not the reviewed one, refuses every key.
        (
            &with_save_chirho,
            "publish-chirho",
            None,
            &read_caps_chirho,
            RouteNotOpenChirho,
        ),
        // A route added later under an old action name never joins an old key.
        (
            &with_save_chirho,
            "agent-page-two-chirho",
            Some("page-read-chirho"),
            &read_caps_chirho,
            ActionNotGrantedChirho,
        ),
        // An opened route whose DAG now publishes refuses even the widest key.
        (
            &with_save_chirho,
            "agent-save-page-chirho",
            Some("page-save-chirho"),
            &publishing_caps_chirho,
            RouteNotOpenChirho,
        ),
        // The same route and action, but its DAG now writes where it only read: the old consent does not cover it.
        (
            &read_only_chirho,
            "agent-page-chirho",
            Some("page-read-chirho"),
            &save_caps_chirho,
            AuthorityChangedChirho,
        ),
    ];
    for (grants_chirho, route_chirho, opened_chirho, caps_chirho, expected_chirho) in cases_chirho {
        assert_eq!(
            limited_key_route_decision_chirho(
                grants_chirho,
                route_chirho,
                opened_chirho,
                caps_chirho
            ),
            Err(expected_chirho),
            "{route_chirho} opened={opened_chirho:?}"
        );
    }
}

#[test]
fn a_harmless_change_that_keeps_or_narrows_capabilities_still_passes_chirho() {
    // Capabilities are bound, implementation bytes are not: a route that now holds fewer capabilities, or the same ones
    // in another order, is still within its grant.
    let with_save_chirho = grants_chirho(&["page-save-chirho"]);
    for caps_chirho in [
        vec![viewer_write_chirho(), viewer_read_chirho()],
        vec![viewer_write_chirho()],
        vec![],
    ] {
        assert!(limited_key_route_decision_chirho(
            &with_save_chirho,
            "agent-save-page-chirho",
            Some("page-save-chirho"),
            &caps_chirho,
        )
        .is_ok());
    }
}

#[test]
fn refusals_carry_fixed_distinct_identities_chirho() {
    let identities_chirho = [
        KeyRouteRefusalChirho::RouteNotOpenChirho.identity_chirho(),
        KeyRouteRefusalChirho::ActionNotGrantedChirho.identity_chirho(),
        KeyRouteRefusalChirho::AuthorityChangedChirho.identity_chirho(),
    ];
    assert_eq!(
        identities_chirho,
        [
            "key-route-not-open-chirho",
            "key-action-not-granted-chirho",
            "key-action-authority-changed-chirho"
        ]
    );
}
