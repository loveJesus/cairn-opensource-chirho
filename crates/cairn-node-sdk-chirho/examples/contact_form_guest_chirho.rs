// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::Deserialize;
use std::string::String;
use std::vec::Vec;

#[derive(Deserialize)]
struct ContactInputChirho {
    #[serde(default)]
    name_chirho: String,
    #[serde(default)]
    email_chirho: String,
    #[serde(default)]
    message_chirho: String,
}

fn contact_form_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let contact_chirho = match serde_json::from_slice::<ContactInputChirho>(input_chirho) {
        Ok(contact_chirho) => contact_chirho,
        Err(_error_chirho) => return contact_error_chirho("Invalid contact payload"),
    };
    if contact_chirho.name_chirho.trim().is_empty()
        || contact_chirho.email_chirho.trim().is_empty()
        || contact_chirho.message_chirho.trim().is_empty()
    {
        return contact_error_chirho("Name, email, and message are required");
    }

    let name_chirho = escape_html_chirho(contact_chirho.name_chirho.trim());
    let email_chirho = escape_html_chirho(contact_chirho.email_chirho.trim());
    let message_chirho = escape_html_chirho(contact_chirho.message_chirho.trim());
    format!(
        "<section data-contact-chirho=\"received\"><h2>Thanks, {name_chirho}</h2><p>We will reply to {email_chirho}.</p><p>{message_chirho}</p></section>"
    )
    .into_bytes()
}

fn contact_error_chirho(message_chirho: &str) -> Vec<u8> {
    format!(
        "<section data-contact-chirho=\"error\"><p>{}</p></section>",
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

cairn_node_sdk_chirho::export_bytes_node_chirho!(contact_form_chirho, contact_form_impl_chirho);
