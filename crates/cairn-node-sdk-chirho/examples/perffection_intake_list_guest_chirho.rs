// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Pure htmx renderer for safe perffection intake query rows; it never renders private body text.

use serde::Deserialize;
use std::string::String;
use std::vec::Vec;

#[derive(Deserialize)]
struct ScopedQueryResponseChirho {
    #[serde(default)]
    rows_chirho: Vec<QueryRowChirho>,
}

#[derive(Deserialize)]
struct QueryRowChirho {
    key_chirho: String,
    value_chirho: String,
}

#[derive(Deserialize)]
struct PerffectionIntakeRecordViewChirho {
    #[serde(default)]
    schema_chirho: String,
    #[serde(default)]
    status_chirho: String,
    #[serde(default)]
    source_chirho: String,
}

fn perffection_intake_list_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let response_chirho = match serde_json::from_slice::<ScopedQueryResponseChirho>(input_chirho) {
        Ok(response_chirho) => response_chirho,
        Err(_error_chirho) => {
            return error_partial_chirho("Could not load perffection intake rows.")
        }
    };
    let mut body_chirho = String::from("<section data-perffection-intake-list-chirho=\"ready\">");
    if response_chirho.rows_chirho.is_empty() {
        body_chirho.push_str("<p>No perffection intake submissions yet.</p></section>");
        return body_chirho.into_bytes();
    }
    body_chirho.push_str("<ul>");
    for row_chirho in response_chirho.rows_chirho {
        let record_chirho =
            serde_json::from_str::<PerffectionIntakeRecordViewChirho>(&row_chirho.value_chirho)
                .unwrap_or(PerffectionIntakeRecordViewChirho {
                    schema_chirho: String::new(),
                    status_chirho: "unknown".to_string(),
                    source_chirho: String::new(),
                });
        let schema_chirho = if record_chirho.schema_chirho == "perffection-intake-record-v1-chirho"
        {
            "perffection-intake-record-v1-chirho"
        } else {
            "unknown"
        };
        let status_chirho = match record_chirho.status_chirho.as_str() {
            "received" => "received",
            "unknown" => "unknown",
            _ => "other",
        };
        let source_chirho = if record_chirho.source_chirho == "perffection-cairn-dogfood-mvp-chirho"
        {
            "dogfood-mvp"
        } else {
            "unknown"
        };
        body_chirho.push_str(&format!(
            "<li data-perffection-intake-row-chirho=\"{status_chirho}\"><code>{}</code><span>{schema_chirho}</span><span>{source_chirho}</span><strong>{status_chirho}</strong></li>",
            escape_html_chirho(&row_chirho.key_chirho)
        ));
    }
    body_chirho.push_str("</ul></section>");
    body_chirho.into_bytes()
}

fn error_partial_chirho(message_chirho: &str) -> Vec<u8> {
    format!(
        "<section data-perffection-intake-list-chirho=\"error\"><p>{}</p></section>",
        escape_html_chirho(message_chirho)
    )
    .into_bytes()
}

fn escape_html_chirho(value_chirho: &str) -> String {
    let mut out_chirho = String::new();
    for char_chirho in value_chirho.chars() {
        match char_chirho {
            '&' => out_chirho.push_str("&amp;"),
            '<' => out_chirho.push_str("&lt;"),
            '>' => out_chirho.push_str("&gt;"),
            '"' => out_chirho.push_str("&quot;"),
            '\'' => out_chirho.push_str("&#39;"),
            _ => out_chirho.push(char_chirho),
        }
    }
    out_chirho
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    perffection_intake_list_chirho,
    perffection_intake_list_impl_chirho
);

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn perffection_intake_list_renders_safe_rows_without_pii_chirho() {
        let input_chirho = br#"{
          "rows_chirho": [
            {
              "key_chirho": "perffection-intake-chirho/submission-001",
              "value_chirho": "{\"schema_chirho\":\"perffection-intake-record-v1-chirho\",\"status_chirho\":\"received\",\"source_chirho\":\"perffection-cairn-dogfood-mvp-chirho\",\"blob_chirho\":{\"ciphertext_chirho\":\"abc123\"}}",
              "value_len_chirho": 120
            }
          ]
        }"#;
        let html_chirho =
            String::from_utf8(perffection_intake_list_impl_chirho(input_chirho)).unwrap();
        assert!(html_chirho.contains("data-perffection-intake-list-chirho=\"ready\""));
        assert!(html_chirho.contains("perffection-intake-chirho/submission-001"));
        assert!(html_chirho.contains("received"));
        assert!(!html_chirho.contains("miriam@example.com"));
        assert!(!html_chirho.contains("blue awning"));
        assert!(!html_chirho.contains("abc123"));
    }

    #[test]
    fn perffection_intake_list_escapes_row_keys_chirho() {
        let input_chirho = br#"{
          "rows_chirho": [
            {
              "key_chirho": "perffection-intake-chirho/<bad>&\"'",
              "value_chirho": "{\"schema_chirho\":\"perffection-intake-record-v1-chirho\",\"status_chirho\":\"received\"}",
              "value_len_chirho": 80
            }
          ]
        }"#;
        let html_chirho =
            String::from_utf8(perffection_intake_list_impl_chirho(input_chirho)).unwrap();
        assert!(html_chirho.contains("perffection-intake-chirho/&lt;bad&gt;&amp;&quot;&#39;"));
        assert!(!html_chirho.contains("<bad>"));
    }
}
