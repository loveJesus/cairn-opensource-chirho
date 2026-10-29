// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The shared page shell: a complete, accessible HTML document with the cairn UI CSS (inlined);
//! pages are JS-free by default (the `/app-chirho/` CSP is `script-src 'none'`), opting into the
//! htmx-lite loader only via `PageChirho { htmx_chirho: true }`. (Partials —
//! htmx fragments swapped into an existing page — are returned by the component helpers, not this.)

use crate::escape_chirho::escape_html_chirho;
use crate::ui_css_chirho::UI_CSS_CHIRHO;

/// A full-page render request. `body_html_chirho` and `head_extra_chirho` are trusted markup the
/// caller has already escaped where needed; `title_chirho` is escaped here.
pub struct PageChirho<'a> {
    pub title_chirho: &'a str,
    pub body_html_chirho: &'a str,
    pub head_extra_chirho: &'a str,
    pub htmx_chirho: bool,
}

/// Render a complete HTML document around `body_html_chirho`.
pub fn page_chirho(page_chirho: &PageChirho) -> String {
    let htmx_chirho = if page_chirho.htmx_chirho {
        "<script src=\"/htmx-lite-chirho.js\" defer></script>"
    } else {
        ""
    };
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n\
<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>{title_chirho}</title>\n\
<style>{css_chirho}</style>\n{head_extra_chirho}{htmx_chirho}\n\
</head>\n<body>\n{body_html_chirho}\n</body>\n</html>\n",
        title_chirho = escape_html_chirho(page_chirho.title_chirho),
        css_chirho = UI_CSS_CHIRHO,
        head_extra_chirho = page_chirho.head_extra_chirho,
        htmx_chirho = htmx_chirho,
        body_html_chirho = page_chirho.body_html_chirho,
    )
}

/// The common case: a JS-free page with a title and body, no extra head markup. App routes are
/// JS-free (the `/app-chirho/` CSP is `script-src 'none'`); for a looser-CSP context that wants
/// htmx, call `page_chirho` with `PageChirho { htmx_chirho: true }`.
pub fn simple_page_chirho(title_chirho: &str, body_html_chirho: &str) -> String {
    page_chirho(&PageChirho {
        title_chirho,
        body_html_chirho,
        head_extra_chirho: "",
        htmx_chirho: false,
    })
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn page_is_a_full_document_with_css_chirho() {
        let html_chirho = simple_page_chirho("Hi", "<p>body</p>");
        assert!(html_chirho.starts_with("<!doctype html>"));
        assert!(html_chirho.contains("<title>Hi</title>"));
        assert!(html_chirho.contains(".btn-chirho")); // inlined CSS present
        assert!(!html_chirho.contains("/htmx-lite-chirho.js")); // JS-free by default (app-route CSP)
        assert!(html_chirho.contains("<p>body</p>"));
    }

    #[test]
    fn explicit_htmx_page_emits_the_loader_chirho() {
        let html_chirho = page_chirho(&PageChirho {
            title_chirho: "Hi",
            body_html_chirho: "<p>body</p>",
            head_extra_chirho: "",
            htmx_chirho: true,
        });
        assert!(html_chirho.contains("/htmx-lite-chirho.js"));
    }

    #[test]
    fn page_title_is_escaped_chirho() {
        let html_chirho = simple_page_chirho("<x>", "");
        assert!(html_chirho.contains("<title>&lt;x&gt;</title>"));
    }
}
