// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Validate a raw form post into a clean MessageV1Chirho (pure: no I/O, no clock, no rand).

use crate::types_chirho::form_post_v1_chirho::FormPostV1Chirho;
use crate::types_chirho::message_v1_chirho::MessageV1Chirho;

/// in raw_form: FormPostV1Chirho, max_length: u32 (pinned) -> out clean_message: MessageV1Chirho
pub fn validate_message_chirho(
    raw_form_chirho: &FormPostV1Chirho,
    max_length_chirho: u32,
) -> Result<MessageV1Chirho, String> {
    let name_chirho = raw_form_chirho.name_chirho.trim();
    let body_chirho = raw_form_chirho.body_chirho.trim();
    if name_chirho.is_empty() {
        return Err("please tell us your name".to_string());
    }
    if body_chirho.is_empty() {
        return Err("the message is empty".to_string());
    }
    if body_chirho.len() > max_length_chirho as usize {
        return Err(format!(
            "the message is longer than {max_length_chirho} characters"
        ));
    }
    Ok(MessageV1Chirho {
        name_chirho: name_chirho.to_string(),
        body_chirho: body_chirho.to_string(),
    })
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn form_chirho(name_chirho: &str, body_chirho: &str) -> FormPostV1Chirho {
        FormPostV1Chirho {
            name_chirho: name_chirho.to_string(),
            body_chirho: body_chirho.to_string(),
        }
    }

    #[test]
    fn validates_and_trims_chirho() {
        let ok_chirho = validate_message_chirho(&form_chirho(" Rosa ", " ciao! "), 2000).unwrap();
        assert_eq!(ok_chirho.name_chirho, "Rosa");
        assert_eq!(ok_chirho.body_chirho, "ciao!");
        assert!(validate_message_chirho(&form_chirho("", "x"), 2000).is_err());
        assert!(validate_message_chirho(&form_chirho("a", ""), 2000).is_err());
        assert!(validate_message_chirho(&form_chirho("a", "toolong"), 3).is_err());
    }
}
