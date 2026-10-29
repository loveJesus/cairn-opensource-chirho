// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Canonical object-field paths used by projection declarations.

use anyhow::{bail, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub const MAX_JSON_FIELD_PATH_BYTES_CHIRHO: usize = 1_024;
pub const MAX_JSON_FIELD_PATH_SEGMENTS_CHIRHO: usize = 64;
pub const MAX_JSON_FIELD_SEGMENT_BYTES_CHIRHO: usize = 256;
pub const MAX_CONSUMED_FIELD_PATHS_CHIRHO: usize = 128;

/// A canonical RFC-6901-style path over object field names.
///
/// Array traversal is rejected later against the typed field graph; a numeric object-field name is
/// therefore legal here. The root path is not a consumable field.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JsonFieldPathChirho {
    canonical_chirho: String,
    segments_chirho: Vec<String>,
}

impl JsonFieldPathChirho {
    pub fn parse_chirho(value_chirho: &str) -> Result<Self> {
        if value_chirho.len() > MAX_JSON_FIELD_PATH_BYTES_CHIRHO {
            bail!("JSON field path exceeds the byte limit");
        }
        if !value_chirho.starts_with('/') {
            bail!("JSON field path must start with '/' and name a field");
        }

        let encoded_segments_chirho: Vec<&str> = value_chirho[1..].split('/').collect();
        if encoded_segments_chirho.len() > MAX_JSON_FIELD_PATH_SEGMENTS_CHIRHO {
            bail!("JSON field path exceeds the segment limit");
        }

        let mut segments_chirho = Vec::with_capacity(encoded_segments_chirho.len());
        for encoded_chirho in encoded_segments_chirho {
            let segment_chirho = decode_segment_chirho(encoded_chirho)?;
            if segment_chirho.is_empty() {
                bail!("JSON field path segments must not be empty");
            }
            if segment_chirho.len() > MAX_JSON_FIELD_SEGMENT_BYTES_CHIRHO {
                bail!("JSON field path segment exceeds the byte limit");
            }
            segments_chirho.push(segment_chirho);
        }

        let canonical_chirho = encode_segments_chirho(&segments_chirho);
        if canonical_chirho != value_chirho {
            bail!("JSON field path is not byte-canonical");
        }

        Ok(Self {
            canonical_chirho,
            segments_chirho,
        })
    }

    pub fn as_str_chirho(&self) -> &str {
        &self.canonical_chirho
    }

    pub fn segments_chirho(&self) -> &[String] {
        &self.segments_chirho
    }

    pub fn is_ancestor_of_chirho(&self, other_chirho: &Self) -> bool {
        self.segments_chirho.len() < other_chirho.segments_chirho.len()
            && other_chirho
                .segments_chirho
                .starts_with(&self.segments_chirho)
    }
}

impl fmt::Debug for JsonFieldPathChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_tuple("JsonFieldPathChirho")
            .field(&self.canonical_chirho)
            .finish()
    }
}

impl Serialize for JsonFieldPathChirho {
    fn serialize<S>(&self, serializer_chirho: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer_chirho.serialize_str(&self.canonical_chirho)
    }
}

impl<'de> Deserialize<'de> for JsonFieldPathChirho {
    fn deserialize<D>(deserializer_chirho: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value_chirho = String::deserialize(deserializer_chirho)?;
        Self::parse_chirho(&value_chirho).map_err(serde::de::Error::custom)
    }
}

pub fn validate_consumed_fields_chirho(fields_chirho: &[JsonFieldPathChirho]) -> Result<()> {
    if fields_chirho.is_empty() {
        bail!("field projection requires at least one consumed field");
    }
    if fields_chirho.len() > MAX_CONSUMED_FIELD_PATHS_CHIRHO {
        bail!("field projection exceeds the consumed-field limit");
    }

    for pair_chirho in fields_chirho.windows(2) {
        let previous_chirho = &pair_chirho[0];
        let current_chirho = &pair_chirho[1];
        if previous_chirho.as_str_chirho() >= current_chirho.as_str_chirho() {
            bail!("consumed fields must be unique and in strict byte order");
        }
    }

    for (index_chirho, field_chirho) in fields_chirho.iter().enumerate() {
        for other_chirho in &fields_chirho[index_chirho + 1..] {
            if field_chirho.is_ancestor_of_chirho(other_chirho)
                || other_chirho.is_ancestor_of_chirho(field_chirho)
            {
                bail!("consumed fields must not contain ancestor/descendant overlap");
            }
        }
    }
    Ok(())
}

fn decode_segment_chirho(encoded_chirho: &str) -> Result<String> {
    let mut decoded_chirho = String::with_capacity(encoded_chirho.len());
    let mut chars_chirho = encoded_chirho.chars();
    while let Some(char_chirho) = chars_chirho.next() {
        if char_chirho != '~' {
            decoded_chirho.push(char_chirho);
            continue;
        }
        match chars_chirho.next() {
            Some('0') => decoded_chirho.push('~'),
            Some('1') => decoded_chirho.push('/'),
            Some(_) | None => bail!("JSON field path has an invalid '~' escape"),
        }
    }
    Ok(decoded_chirho)
}

fn encode_segments_chirho(segments_chirho: &[String]) -> String {
    let mut encoded_chirho = String::new();
    for segment_chirho in segments_chirho {
        encoded_chirho.push('/');
        for char_chirho in segment_chirho.chars() {
            match char_chirho {
                '~' => encoded_chirho.push_str("~0"),
                '/' => encoded_chirho.push_str("~1"),
                _ => encoded_chirho.push(char_chirho),
            }
        }
    }
    encoded_chirho
}
