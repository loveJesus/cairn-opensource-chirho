// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The single correct HTML escape for cairn apps — centralizing what was copy-pasted across guests
//! (contact, intake, …). One implementation, one place to audit: untrusted user data can never
//! break out of element content or a double-quoted attribute.

/// Escape text for safe insertion into HTML element content or a double-quoted attribute.
/// Handles `&`, `<`, `>`, `"`, and `'`.
pub fn escape_html_chirho(value_chirho: &str) -> String {
    let mut out_chirho = String::with_capacity(value_chirho.len() + 16);
    for ch_chirho in value_chirho.chars() {
        match ch_chirho {
            '&' => out_chirho.push_str("&amp;"),
            '<' => out_chirho.push_str("&lt;"),
            '>' => out_chirho.push_str("&gt;"),
            '"' => out_chirho.push_str("&quot;"),
            '\'' => out_chirho.push_str("&#39;"),
            _ => out_chirho.push(ch_chirho),
        }
    }
    out_chirho
}

/// Attribute-context escape. We always quote attributes with double quotes, so the rules match
/// element content; the distinct name keeps call sites intent-clear.
pub fn escape_attr_chirho(value_chirho: &str) -> String {
    escape_html_chirho(value_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn escapes_all_dangerous_chars_chirho() {
        assert_eq!(
            escape_html_chirho("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&#39;f"
        );
    }

    #[test]
    fn blocks_script_breakout_chirho() {
        let safe_chirho = escape_html_chirho("</script><script>alert(1)</script>");
        assert!(!safe_chirho.contains("<script>"));
        assert!(!safe_chirho.contains("</script>"));
    }

    #[test]
    fn leaves_safe_text_unchanged_chirho() {
        assert_eq!(escape_html_chirho("Hello, world 123"), "Hello, world 123");
    }
}
