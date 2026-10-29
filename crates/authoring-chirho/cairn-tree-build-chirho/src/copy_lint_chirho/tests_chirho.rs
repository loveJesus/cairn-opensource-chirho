// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

fn policy_chirho(terms_chirho: &[&str]) -> RenderedCopyLintPolicyChirho {
    RenderedCopyLintPolicyChirho {
        blocked_terms_chirho: terms_chirho
            .iter()
            .map(|term_chirho| RenderedCopyLintTermChirho {
                term_chirho: term_chirho.to_string(),
                category_chirho: Some("implementation-language-chirho".to_string()),
                hint_chirho: None,
            })
            .collect(),
        ..RenderedCopyLintPolicyChirho::default()
    }
}

#[test]
fn public_route_lints_visible_copy_only_chirho() {
    let html_chirho = r#"<!doctype html>
<meta name="description" content="Cairn is in an attribute">
<!-- proof note hidden in a comment -->
<style>.cairn { color: red }</style>
<script>console.log("manifest")</script>
<main><h1>Plan your visit</h1><p>This page mentions Cairn proof copy.</p></main>"#;
    let findings_chirho = lint_rendered_html_copy_chirho(
        html_chirho,
        "public_chirho",
        &policy_chirho(&["Cairn", "proof", "manifest"]),
    );
    assert_eq!(findings_chirho.len(), 2);
    assert_eq!(findings_chirho[0].term_chirho, "Cairn");
    assert_eq!(findings_chirho[1].term_chirho, "proof");
    assert!(findings_chirho[0]
        .snippet_chirho
        .contains("This page mentions Cairn"));
    assert!(!findings_chirho
        .iter()
        .any(|finding_chirho| finding_chirho.term_chirho == "manifest"));
}

#[test]
fn technical_routes_are_not_copy_linted_chirho() {
    let html_chirho = "<main>Cairn DAG manifest proof evidence</main>";
    let findings_chirho = lint_rendered_html_copy_chirho(
        html_chirho,
        "evidence_chirho",
        &policy_chirho(&["Cairn", "DAG", "manifest"]),
    );
    assert!(findings_chirho.is_empty());
}

#[test]
fn configured_terms_are_word_boundary_matched_chirho() {
    let html_chirho = "<main>The manifesto is fine. The manifest is not.</main>";
    let findings_chirho =
        lint_rendered_html_copy_chirho(html_chirho, "public_chirho", &policy_chirho(&["manifest"]));
    assert_eq!(findings_chirho.len(), 1);
    assert!(findings_chirho[0]
        .snippet_chirho
        .contains("The manifest is not"));
}

#[test]
fn rendered_visible_text_inserts_tag_word_boundaries_chirho() {
    let text_chirho = rendered_visible_text_chirho("<h1>Welcome</h1><p>Plan your visit</p>");
    assert_eq!(text_chirho, "Welcome Plan your visit");
}

#[test]
fn policy_toml_parses_with_configurable_categories_chirho() {
    let policy_text_chirho = r#"
schema_chirho = "rendered-copy-lint-policy-v1-chirho"
public_route_kinds_chirho = ["public_chirho", "visitor_chirho"]
technical_route_kinds_chirho = ["admin_chirho"]
snippet_radius_chirho = 24
max_findings_chirho = 3

[[blocked_terms_chirho]]
term_chirho = "Cairn"
category_chirho = "implementation-language-chirho"
hint_chirho = "Use visitor language."
"#;
    let policy_chirho: RenderedCopyLintPolicyChirho = toml::from_str(policy_text_chirho).unwrap();
    assert!(route_kind_is_public_copy_linted_chirho(
        &policy_chirho,
        "visitor_chirho"
    ));
    assert!(!route_kind_is_public_copy_linted_chirho(
        &policy_chirho,
        "admin_chirho"
    ));
    let findings_chirho = lint_rendered_html_copy_chirho(
        "<main>Cairn internals</main>",
        "visitor_chirho",
        &policy_chirho,
    );
    assert_eq!(findings_chirho.len(), 1);
    assert_eq!(
        findings_chirho[0].category_chirho.as_deref(),
        Some("implementation-language-chirho")
    );
    assert_eq!(findings_chirho[0].hint_chirho, "Use visitor language.");
}

#[test]
fn route_kind_disposition_fails_closed_on_unknown_chirho() {
    let policy_chirho = RenderedCopyLintPolicyChirho {
        unlinted_route_kinds_chirho: vec!["legacy_unlinted_chirho".to_string()],
        ..RenderedCopyLintPolicyChirho::default()
    };
    assert_eq!(
        route_kind_disposition_chirho(&policy_chirho, "public_chirho"),
        RenderedCopyLintRouteDispositionChirho::LintChirho
    );
    assert_eq!(
        route_kind_disposition_chirho(&policy_chirho, "evidence_chirho"),
        RenderedCopyLintRouteDispositionChirho::SkipChirho
    );
    assert_eq!(
        route_kind_disposition_chirho(&policy_chirho, "legacy_unlinted_chirho"),
        RenderedCopyLintRouteDispositionChirho::SkipChirho
    );
    assert_eq!(
        route_kind_disposition_chirho(&policy_chirho, "pubic_chirho"),
        RenderedCopyLintRouteDispositionChirho::UnknownChirho
    );
}
