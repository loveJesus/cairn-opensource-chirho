// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Rendered HTML copy lint for public app routes. This runs on served/rendered output, not source,
//! so evidence docs and operator code can still use technical words while public visitor pages stay
//! free of implementation/proof language.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// A configured visible-copy term that is not allowed on public visitor routes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedCopyLintTermChirho {
    pub term_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint_chirho: Option<String>,
}

/// Per-app policy for rendered public-copy lint. Keep the mechanism generic and the words plastic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedCopyLintPolicyChirho {
    #[serde(default = "default_schema_chirho")]
    pub schema_chirho: String,
    #[serde(default = "default_public_route_kinds_chirho")]
    pub public_route_kinds_chirho: Vec<String>,
    #[serde(default = "default_technical_route_kinds_chirho")]
    pub technical_route_kinds_chirho: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlinted_route_kinds_chirho: Vec<String>,
    #[serde(default)]
    pub blocked_terms_chirho: Vec<RenderedCopyLintTermChirho>,
    #[serde(default = "default_snippet_radius_chirho")]
    pub snippet_radius_chirho: usize,
    #[serde(default = "default_max_findings_chirho")]
    pub max_findings_chirho: usize,
}

impl Default for RenderedCopyLintPolicyChirho {
    fn default() -> Self {
        Self {
            schema_chirho: default_schema_chirho(),
            public_route_kinds_chirho: default_public_route_kinds_chirho(),
            technical_route_kinds_chirho: default_technical_route_kinds_chirho(),
            unlinted_route_kinds_chirho: Vec::new(),
            blocked_terms_chirho: Vec::new(),
            snippet_radius_chirho: default_snippet_radius_chirho(),
            max_findings_chirho: default_max_findings_chirho(),
        }
    }
}

/// One finding from a public rendered-copy lint run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedCopyLintFindingChirho {
    pub code_chirho: String,
    pub route_kind_chirho: String,
    pub term_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category_chirho: Option<String>,
    pub snippet_chirho: String,
    pub message_chirho: String,
    pub hint_chirho: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderedCopyLintRouteDispositionChirho {
    LintChirho,
    SkipChirho,
    UnknownChirho,
}

fn default_schema_chirho() -> String {
    "rendered-copy-lint-policy-v1-chirho".to_string()
}

fn default_public_route_kinds_chirho() -> Vec<String> {
    vec!["public_chirho".to_string()]
}

fn default_technical_route_kinds_chirho() -> Vec<String> {
    vec![
        "admin_chirho".to_string(),
        "debug_chirho".to_string(),
        "evidence_chirho".to_string(),
        "operator_chirho".to_string(),
    ]
}

fn default_snippet_radius_chirho() -> usize {
    48
}

fn default_max_findings_chirho() -> usize {
    50
}

pub fn load_rendered_copy_lint_policy_chirho(
    path_chirho: &Path,
) -> Result<RenderedCopyLintPolicyChirho, String> {
    let text_chirho = std::fs::read_to_string(path_chirho)
        .map_err(|e_chirho| format!("read rendered copy lint policy: {e_chirho}"))?;
    toml::from_str(&text_chirho)
        .map_err(|e_chirho| format!("parse rendered copy lint policy: {e_chirho}"))
}

fn contains_route_kind_chirho(kinds_chirho: &[String], route_kind_chirho: &str) -> bool {
    kinds_chirho
        .iter()
        .any(|kind_chirho| kind_chirho == route_kind_chirho)
}

pub fn route_kind_disposition_chirho(
    policy_chirho: &RenderedCopyLintPolicyChirho,
    route_kind_chirho: &str,
) -> RenderedCopyLintRouteDispositionChirho {
    if contains_route_kind_chirho(
        &policy_chirho.technical_route_kinds_chirho,
        route_kind_chirho,
    ) {
        return RenderedCopyLintRouteDispositionChirho::SkipChirho;
    }
    if contains_route_kind_chirho(
        &policy_chirho.unlinted_route_kinds_chirho,
        route_kind_chirho,
    ) {
        return RenderedCopyLintRouteDispositionChirho::SkipChirho;
    }
    if contains_route_kind_chirho(&policy_chirho.public_route_kinds_chirho, route_kind_chirho) {
        return RenderedCopyLintRouteDispositionChirho::LintChirho;
    }
    RenderedCopyLintRouteDispositionChirho::UnknownChirho
}

pub fn route_kind_is_public_copy_linted_chirho(
    policy_chirho: &RenderedCopyLintPolicyChirho,
    route_kind_chirho: &str,
) -> bool {
    route_kind_disposition_chirho(policy_chirho, route_kind_chirho)
        == RenderedCopyLintRouteDispositionChirho::LintChirho
}

/// Lint rendered HTML for public-route implementation/proof copy.
pub fn lint_rendered_html_copy_chirho(
    html_chirho: &str,
    route_kind_chirho: &str,
    policy_chirho: &RenderedCopyLintPolicyChirho,
) -> Vec<RenderedCopyLintFindingChirho> {
    if !route_kind_is_public_copy_linted_chirho(policy_chirho, route_kind_chirho) {
        return Vec::new();
    }
    let visible_text_chirho = rendered_visible_text_chirho(html_chirho);
    let visible_lower_chirho = visible_text_chirho.to_ascii_lowercase();
    let mut findings_chirho = Vec::new();
    let max_findings_chirho = policy_chirho.max_findings_chirho.max(1);
    let snippet_radius_chirho = policy_chirho.snippet_radius_chirho.min(120);

    for term_chirho in &policy_chirho.blocked_terms_chirho {
        let term_text_chirho = term_chirho.term_chirho.trim();
        if term_text_chirho.is_empty() {
            continue;
        }
        let term_lower_chirho = term_text_chirho.to_ascii_lowercase();
        let mut search_from_chirho = 0;
        while let Some(relative_chirho) =
            visible_lower_chirho[search_from_chirho..].find(&term_lower_chirho)
        {
            let start_chirho = search_from_chirho + relative_chirho;
            let end_chirho = start_chirho + term_lower_chirho.len();
            search_from_chirho = end_chirho;
            if !term_boundary_matches_chirho(&visible_lower_chirho, start_chirho, end_chirho) {
                continue;
            }
            findings_chirho.push(RenderedCopyLintFindingChirho {
                code_chirho: "public-copy-blocked-term-chirho".to_string(),
                route_kind_chirho: route_kind_chirho.to_string(),
                term_chirho: term_text_chirho.to_string(),
                category_chirho: term_chirho.category_chirho.clone(),
                snippet_chirho: snippet_chirho(
                    &visible_text_chirho,
                    start_chirho,
                    end_chirho,
                    snippet_radius_chirho,
                ),
                message_chirho:
                    "public rendered copy contains implementation or proof language".to_string(),
                hint_chirho: term_chirho.hint_chirho.clone().unwrap_or_else(|| {
                    "rewrite public visitor copy in product/user language, or mark the route as admin/evidence/debug if technical terms are intentional".to_string()
                }),
            });
            if findings_chirho.len() >= max_findings_chirho {
                return findings_chirho;
            }
        }
    }

    findings_chirho
}

fn push_visible_char_chirho(out_chirho: &mut String, ch_chirho: char) {
    if ch_chirho.is_whitespace() {
        if !out_chirho.ends_with(' ') && !out_chirho.is_empty() {
            out_chirho.push(' ');
        }
    } else {
        out_chirho.push(ch_chirho);
    }
}

fn decode_entity_chirho(entity_chirho: &str) -> Option<char> {
    match entity_chirho {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" | "#39" => Some('\''),
        "nbsp" => Some(' '),
        _ => None,
    }
}

fn tag_name_chirho(tag_chirho: &str) -> String {
    tag_chirho
        .trim_start()
        .trim_start_matches('/')
        .trim_start_matches('!')
        .trim_start_matches('?')
        .split(|ch_chirho: char| ch_chirho.is_whitespace() || ch_chirho == '/' || ch_chirho == '>')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn skip_until_case_insensitive_chirho(
    html_chirho: &str,
    mut index_chirho: usize,
    needle_chirho: &str,
) -> usize {
    let lower_chirho = html_chirho[index_chirho..].to_ascii_lowercase();
    if let Some(relative_chirho) = lower_chirho.find(needle_chirho) {
        index_chirho += relative_chirho + needle_chirho.len();
    } else {
        index_chirho = html_chirho.len();
    }
    index_chirho
}

/// Extract a conservative visible-text stream from HTML. It skips tags, comments, scripts, and
/// styles so attributes and implementation scaffolding do not trigger public-copy findings.
pub fn rendered_visible_text_chirho(html_chirho: &str) -> String {
    let mut out_chirho = String::new();
    let mut index_chirho = 0;
    while index_chirho < html_chirho.len() {
        let rest_chirho = &html_chirho[index_chirho..];
        if rest_chirho.starts_with("<!--") {
            if let Some(end_chirho) = rest_chirho.find("-->") {
                index_chirho += end_chirho + 3;
            } else {
                break;
            }
            continue;
        }
        if rest_chirho.starts_with('<') {
            if let Some(end_chirho) = rest_chirho.find('>') {
                let tag_chirho = &rest_chirho[1..end_chirho];
                let name_chirho = tag_name_chirho(tag_chirho);
                index_chirho += end_chirho + 1;
                if !tag_chirho.trim_start().starts_with('/')
                    && (name_chirho == "script" || name_chirho == "style")
                {
                    index_chirho = skip_until_case_insensitive_chirho(
                        html_chirho,
                        index_chirho,
                        &format!("</{name_chirho}"),
                    );
                    if index_chirho < html_chirho.len() {
                        if let Some(close_chirho) = html_chirho[index_chirho..].find('>') {
                            index_chirho += close_chirho + 1;
                        }
                    }
                }
                push_visible_char_chirho(&mut out_chirho, ' ');
            } else {
                break;
            }
            continue;
        }
        if rest_chirho.starts_with('&') {
            if let Some(end_chirho) = rest_chirho.find(';') {
                if end_chirho <= 12 {
                    let entity_chirho = &rest_chirho[1..end_chirho];
                    if let Some(decoded_chirho) = decode_entity_chirho(entity_chirho) {
                        push_visible_char_chirho(&mut out_chirho, decoded_chirho);
                        index_chirho += end_chirho + 1;
                        continue;
                    }
                }
            }
        }
        let Some(ch_chirho) = rest_chirho.chars().next() else {
            break;
        };
        push_visible_char_chirho(&mut out_chirho, ch_chirho);
        index_chirho += ch_chirho.len_utf8();
    }
    out_chirho.trim().to_string()
}

fn boundary_char_chirho(ch_chirho: Option<char>) -> bool {
    match ch_chirho {
        None => true,
        Some(ch_chirho) => !ch_chirho.is_ascii_alphanumeric(),
    }
}

fn term_boundary_matches_chirho(text_chirho: &str, start_chirho: usize, end_chirho: usize) -> bool {
    let before_chirho = text_chirho[..start_chirho].chars().next_back();
    let after_chirho = text_chirho[end_chirho..].chars().next();
    boundary_char_chirho(before_chirho) && boundary_char_chirho(after_chirho)
}

fn char_boundary_before_or_at_chirho(text_chirho: &str, index_chirho: usize) -> usize {
    let mut out_chirho = 0;
    for (i_chirho, _ch_chirho) in text_chirho.char_indices() {
        if i_chirho > index_chirho {
            break;
        }
        out_chirho = i_chirho;
    }
    out_chirho
}

fn char_boundary_after_or_at_chirho(text_chirho: &str, index_chirho: usize) -> usize {
    for (i_chirho, _ch_chirho) in text_chirho.char_indices() {
        if i_chirho >= index_chirho {
            return i_chirho;
        }
    }
    text_chirho.len()
}

fn snippet_chirho(
    text_chirho: &str,
    start_chirho: usize,
    end_chirho: usize,
    radius_chirho: usize,
) -> String {
    let from_chirho =
        char_boundary_before_or_at_chirho(text_chirho, start_chirho.saturating_sub(radius_chirho));
    let to_chirho = char_boundary_after_or_at_chirho(
        text_chirho,
        end_chirho
            .saturating_add(radius_chirho)
            .min(text_chirho.len()),
    );
    let mut snippet_chirho = String::new();
    if from_chirho > 0 {
        snippet_chirho.push_str("...");
    }
    snippet_chirho.push_str(text_chirho[from_chirho..to_chirho].trim());
    if to_chirho < text_chirho.len() {
        snippet_chirho.push_str("...");
    }
    snippet_chirho
}

#[cfg(test)]
mod tests_chirho;
