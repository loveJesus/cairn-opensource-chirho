// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
//! Build-time static page assembler: substitute `{{var}}` and include `{{> partial}}` in a layout, failing closed on anything unknown.
//!
//! This is a trusted-input build tool for developer-authored templates and values; it performs
//! no HTML escaping and must not be fed untrusted user input.

use std::collections::BTreeMap;
use std::fmt;

/// Maximum partial-include nesting before rendering fails (cycle guard).
pub const MAX_DEPTH_CHIRHO: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum PagesErrorChirho {
    UnknownVarChirho(String),
    UnknownPartialChirho(String),
    UnclosedTagChirho(usize),
    EmptyTagChirho(usize),
    DepthExceededChirho(String),
}

impl fmt::Display for PagesErrorChirho {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVarChirho(name_chirho) => write!(f, "unknown var: {name_chirho}"),
            Self::UnknownPartialChirho(name_chirho) => write!(f, "unknown partial: {name_chirho}"),
            Self::UnclosedTagChirho(at_chirho) => write!(f, "unclosed {{{{ at byte {at_chirho}"),
            Self::EmptyTagChirho(at_chirho) => write!(f, "empty tag at byte {at_chirho}"),
            Self::DepthExceededChirho(name_chirho) => {
                write!(f, "partial depth exceeded at: {name_chirho}")
            }
        }
    }
}

impl std::error::Error for PagesErrorChirho {}

/// Render `template`, replacing `{{name}}` from `vars` and `{{> name}}` from `partials`.
/// Partials may themselves contain tags; nesting beyond [`MAX_DEPTH_CHIRHO`] fails closed.
pub fn render_chirho(
    template_chirho: &str,
    vars_chirho: &BTreeMap<String, String>,
    partials_chirho: &BTreeMap<String, String>,
) -> Result<String, PagesErrorChirho> {
    render_depth_chirho(template_chirho, vars_chirho, partials_chirho, 0)
}

fn render_depth_chirho(
    template_chirho: &str,
    vars_chirho: &BTreeMap<String, String>,
    partials_chirho: &BTreeMap<String, String>,
    depth_chirho: usize,
) -> Result<String, PagesErrorChirho> {
    let mut out_chirho = String::with_capacity(template_chirho.len());
    let mut rest_chirho = template_chirho;
    let mut offset_chirho = 0usize;
    while let Some(open_chirho) = rest_chirho.find("{{") {
        out_chirho.push_str(&rest_chirho[..open_chirho]);
        let after_open_chirho = &rest_chirho[open_chirho + 2..];
        let close_chirho =
            after_open_chirho
                .find("}}")
                .ok_or(PagesErrorChirho::UnclosedTagChirho(
                    offset_chirho + open_chirho,
                ))?;
        let raw_tag_chirho = &after_open_chirho[..close_chirho];
        let tag_chirho = raw_tag_chirho.trim();
        if tag_chirho.is_empty() {
            return Err(PagesErrorChirho::EmptyTagChirho(
                offset_chirho + open_chirho,
            ));
        }
        if let Some(partial_name_chirho) = tag_chirho.strip_prefix('>') {
            let name_chirho = partial_name_chirho.trim();
            let body_chirho = partials_chirho
                .get(name_chirho)
                .ok_or_else(|| PagesErrorChirho::UnknownPartialChirho(name_chirho.to_string()))?;
            if depth_chirho + 1 > MAX_DEPTH_CHIRHO {
                return Err(PagesErrorChirho::DepthExceededChirho(
                    name_chirho.to_string(),
                ));
            }
            out_chirho.push_str(&render_depth_chirho(
                body_chirho,
                vars_chirho,
                partials_chirho,
                depth_chirho + 1,
            )?);
        } else {
            let value_chirho = vars_chirho
                .get(tag_chirho)
                .ok_or_else(|| PagesErrorChirho::UnknownVarChirho(tag_chirho.to_string()))?;
            out_chirho.push_str(value_chirho);
        }
        let consumed_chirho = open_chirho + 2 + close_chirho + 2;
        offset_chirho += consumed_chirho;
        rest_chirho = &rest_chirho[consumed_chirho..];
    }
    out_chirho.push_str(rest_chirho);
    Ok(out_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn vars_chirho(pairs_chirho: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs_chirho
            .iter()
            .map(|(k_chirho, v_chirho)| (k_chirho.to_string(), v_chirho.to_string()))
            .collect()
    }

    #[test]
    fn substitutes_vars_chirho() {
        let out_chirho = render_chirho(
            "<title>{{title_chirho}}</title>",
            &vars_chirho(&[("title_chirho", "Privacy")]),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(out_chirho, "<title>Privacy</title>");
    }

    #[test]
    fn includes_partials_recursively_chirho() {
        let mut partials_chirho = BTreeMap::new();
        partials_chirho.insert(
            "footer_chirho".to_string(),
            "<footer>{{> year_chirho}}</footer>".to_string(),
        );
        partials_chirho.insert("year_chirho".to_string(), "{{year_chirho}}".to_string());
        let out_chirho = render_chirho(
            "page {{> footer_chirho}}",
            &vars_chirho(&[("year_chirho", "2026")]),
            &partials_chirho,
        )
        .unwrap();
        assert_eq!(out_chirho, "page <footer>2026</footer>");
    }

    #[test]
    fn unknown_var_fails_closed_chirho() {
        let err_chirho =
            render_chirho("{{missing_chirho}}", &BTreeMap::new(), &BTreeMap::new()).unwrap_err();
        assert_eq!(
            err_chirho,
            PagesErrorChirho::UnknownVarChirho("missing_chirho".to_string())
        );
    }

    #[test]
    fn unknown_partial_fails_closed_chirho() {
        let err_chirho =
            render_chirho("{{> missing_chirho}}", &BTreeMap::new(), &BTreeMap::new()).unwrap_err();
        assert_eq!(
            err_chirho,
            PagesErrorChirho::UnknownPartialChirho("missing_chirho".to_string())
        );
    }

    #[test]
    fn unclosed_tag_fails_closed_chirho() {
        let err_chirho =
            render_chirho("ok {{title", &BTreeMap::new(), &BTreeMap::new()).unwrap_err();
        assert_eq!(err_chirho, PagesErrorChirho::UnclosedTagChirho(3));
    }

    #[test]
    fn empty_tag_fails_closed_chirho() {
        let err_chirho = render_chirho("{{  }}", &BTreeMap::new(), &BTreeMap::new()).unwrap_err();
        assert_eq!(err_chirho, PagesErrorChirho::EmptyTagChirho(0));
    }

    #[test]
    fn partial_cycle_fails_closed_chirho() {
        let mut partials_chirho = BTreeMap::new();
        partials_chirho.insert("a_chirho".to_string(), "{{> a_chirho}}".to_string());
        let err_chirho =
            render_chirho("{{> a_chirho}}", &BTreeMap::new(), &partials_chirho).unwrap_err();
        assert_eq!(
            err_chirho,
            PagesErrorChirho::DepthExceededChirho("a_chirho".to_string())
        );
    }

    #[test]
    fn value_containing_tag_syntax_is_not_reexpanded_chirho() {
        let out_chirho = render_chirho(
            "{{content_chirho}}",
            &vars_chirho(&[("content_chirho", "literal {{not_a_var_chirho}}")]),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(out_chirho, "literal {{not_a_var_chirho}}");
    }
}
