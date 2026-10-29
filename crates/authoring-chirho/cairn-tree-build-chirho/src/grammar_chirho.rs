// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The connection-name segment grammar: `{in,out}-<name>-<type>-chirho[-<base32 tag>]`,
//! segments hyphen-separated, `[a-z0-9_]` inside a segment, parsed positionally and fail-closed.

use serde::{Deserialize, Serialize};

pub const BASE32_TAG_LEN_CHIRHO: usize = 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectionChirho {
    InChirho,
    OutChirho,
}

/// A parsed connection dir/link name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionNameChirho {
    pub direction_chirho: DirectionChirho,
    pub name_chirho: String,
    pub type_name_chirho: String,
    /// Full 256-bit namespace tag, unpadded lowercase base32 (52 chars), when imported.
    pub namespace_tag_chirho: Option<String>,
}

/// One self-contained, machine-applicable diagnostic (the LLM-codegen-friendly shape).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrammarErrorChirho {
    pub code_chirho: String,
    pub input_chirho: String,
    pub message_chirho: String,
    pub expected_chirho: String,
    pub found_chirho: String,
    pub hint_chirho: String,
}

fn segment_ok_chirho(segment_chirho: &str) -> bool {
    !segment_chirho.is_empty()
        && segment_chirho.bytes().all(|b_chirho| {
            b_chirho.is_ascii_lowercase() || b_chirho.is_ascii_digit() || b_chirho == b'_'
        })
}

fn base32_tag_ok_chirho(tag_chirho: &str) -> bool {
    // Unpadded lowercase RFC 4648 base32 (a-z, 2-7), fixed length; the final char carries
    // 4 spare bits which MUST be zero => its value is a multiple of 16 => 'a' or 'q'.
    tag_chirho.len() == BASE32_TAG_LEN_CHIRHO
        && tag_chirho
            .bytes()
            .all(|b_chirho| b_chirho.is_ascii_lowercase() || (b'2'..=b'7').contains(&b_chirho))
        && matches!(
            tag_chirho.as_bytes()[BASE32_TAG_LEN_CHIRHO - 1],
            b'a' | b'q'
        )
}

fn error_chirho(
    code_chirho: &str,
    input_chirho: &str,
    message_chirho: &str,
    expected_chirho: &str,
    found_chirho: &str,
    hint_chirho: &str,
) -> Box<GrammarErrorChirho> {
    Box::new(GrammarErrorChirho {
        code_chirho: code_chirho.to_string(),
        input_chirho: input_chirho.to_string(),
        message_chirho: message_chirho.to_string(),
        expected_chirho: expected_chirho.to_string(),
        found_chirho: found_chirho.to_string(),
        hint_chirho: hint_chirho.to_string(),
    })
}

/// Parse a connection dir/link name. Positional: 4 segments = app-local type, 5 = imported.
pub fn parse_connection_name_chirho(
    input_chirho: &str,
) -> Result<ConnectionNameChirho, Box<GrammarErrorChirho>> {
    let segments_chirho: Vec<&str> = input_chirho.split('-').collect();
    if segments_chirho.len() != 4 && segments_chirho.len() != 5 {
        return Err(error_chirho(
            "grammar-segment-count-chirho",
            input_chirho,
            "a connection name has 4 segments (local type) or 5 (imported type)",
            "{in,out}-<name>-<type>-chirho[-<52-char base32 tag>]",
            &format!("{} segments", segments_chirho.len()),
            "separate segments with single hyphens; use underscores as spaces inside a segment",
        ));
    }
    let direction_chirho = match segments_chirho[0] {
        "in" => DirectionChirho::InChirho,
        "out" => DirectionChirho::OutChirho,
        other_chirho => {
            return Err(error_chirho(
                "grammar-direction-chirho",
                input_chirho,
                "the first segment must be the direction",
                "`in` or `out`",
                other_chirho,
                "rename the dir/link to start with `in-` (consumes) or `out-` (produces)",
            ))
        }
    };
    for (label_chirho, segment_chirho) in
        [("name", segments_chirho[1]), ("type", segments_chirho[2])]
    {
        if !segment_ok_chirho(segment_chirho) {
            return Err(error_chirho(
                "grammar-segment-charset-chirho",
                input_chirho,
                &format!("the {label_chirho} segment has characters outside the grammar"),
                "lowercase letters, digits, and underscores only",
                segment_chirho,
                "use underscores as spaces; hyphens only BETWEEN segments",
            ));
        }
    }
    if segments_chirho[3] != "chirho" {
        return Err(error_chirho(
            "grammar-chirho-suffix-chirho",
            input_chirho,
            "the fourth segment must be the literal `chirho`",
            "chirho",
            segments_chirho[3],
            "end the name with `-chirho` (the namespace tag, if any, rides after it)",
        ));
    }
    let namespace_tag_chirho = if segments_chirho.len() == 5 {
        let tag_chirho = segments_chirho[4];
        if !base32_tag_ok_chirho(tag_chirho) {
            return Err(error_chirho(
                "grammar-namespace-tag-chirho",
                input_chirho,
                "the namespace tag must be a full 256-bit hash, unpadded lowercase base32",
                "52 chars of [a-z2-7], final char `a` or `q` (4 spare bits zero — one spelling per stone)",
                tag_chirho,
                "copy the tag from the type's catalog entry; never hand-shorten a hash",
            ));
        }
        Some(tag_chirho.to_string())
    } else {
        None
    };
    Ok(ConnectionNameChirho {
        direction_chirho,
        name_chirho: segments_chirho[1].to_string(),
        type_name_chirho: segments_chirho[2].to_string(),
        namespace_tag_chirho,
    })
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn parses_local_and_imported_connection_names_chirho() {
        let local_chirho =
            parse_connection_name_chirho("out-clean_message-message_v1-chirho").unwrap();
        assert_eq!(local_chirho.direction_chirho, DirectionChirho::OutChirho);
        assert_eq!(local_chirho.name_chirho, "clean_message");
        assert_eq!(local_chirho.type_name_chirho, "message_v1");
        assert!(local_chirho.namespace_tag_chirho.is_none());

        let tag_chirho = format!("{}a", "b".repeat(BASE32_TAG_LEN_CHIRHO - 1));
        let imported_chirho =
            parse_connection_name_chirho(&format!("in-receipt-receipt_v1-chirho-{tag_chirho}"))
                .unwrap();
        assert_eq!(imported_chirho.direction_chirho, DirectionChirho::InChirho);
        assert_eq!(
            imported_chirho.namespace_tag_chirho.as_deref(),
            Some(tag_chirho.as_str())
        );
    }

    #[test]
    fn rejects_bad_names_with_self_contained_diagnostics_chirho() {
        for (input_chirho, code_chirho) in [
            ("sideways-x-y-chirho", "grammar-direction-chirho"),
            ("out-Bad_Case-y-chirho", "grammar-segment-charset-chirho"),
            ("out-x-y-z", "grammar-chirho-suffix-chirho"),
            ("out-x-y", "grammar-segment-count-chirho"),
            ("out-x-y-chirho-tooshort", "grammar-namespace-tag-chirho"),
        ] {
            let error_chirho = parse_connection_name_chirho(input_chirho).unwrap_err();
            assert_eq!(error_chirho.code_chirho, code_chirho, "{input_chirho}");
            assert!(!error_chirho.hint_chirho.is_empty());
            assert_eq!(error_chirho.input_chirho, input_chirho);
        }
    }

    #[test]
    fn canonical_base32_final_char_rule_holds_chirho() {
        let good_chirho = format!("{}q", "c".repeat(BASE32_TAG_LEN_CHIRHO - 1));
        assert!(parse_connection_name_chirho(&format!("in-x-y-chirho-{good_chirho}")).is_ok());
        let bad_chirho = format!("{}b", "c".repeat(BASE32_TAG_LEN_CHIRHO - 1));
        assert_eq!(
            parse_connection_name_chirho(&format!("in-x-y-chirho-{bad_chirho}"))
                .unwrap_err()
                .code_chirho,
            "grammar-namespace-tag-chirho"
        );
    }
}
