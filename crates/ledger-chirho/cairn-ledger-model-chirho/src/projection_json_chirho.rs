// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! One explicit canonical-JSON byte law for disposable ledger projections.
//!
//! Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.

use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::error::Error;
use std::fmt;

/// Exact-canonical projection JSON failures, separated so callers can retain a typed refusal.
#[derive(Debug)]
pub enum CanonicalProjectionJsonErrorChirho {
    DecodeChirho(serde_json::Error),
    EncodeChirho(serde_json::Error),
    NonCanonicalChirho,
}

impl fmt::Display for CanonicalProjectionJsonErrorChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecodeChirho(error_chirho) => {
                write!(formatter_chirho, "decode projection JSON: {error_chirho}")
            }
            Self::EncodeChirho(error_chirho) => {
                write!(formatter_chirho, "encode projection JSON: {error_chirho}")
            }
            Self::NonCanonicalChirho => {
                formatter_chirho.write_str("projection JSON is not exact-canonical")
            }
        }
    }
}

impl Error for CanonicalProjectionJsonErrorChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DecodeChirho(error_chirho) | Self::EncodeChirho(error_chirho) => {
                Some(error_chirho)
            }
            Self::NonCanonicalChirho => None,
        }
    }
}

struct CanonicalProjectionJsonValueChirho<'value_chirho>(&'value_chirho Value);

impl Serialize for CanonicalProjectionJsonValueChirho<'_> {
    fn serialize<SerializerChirho>(
        &self,
        serializer_chirho: SerializerChirho,
    ) -> Result<SerializerChirho::Ok, SerializerChirho::Error>
    where
        SerializerChirho: Serializer,
    {
        match self.0 {
            Value::Null => serializer_chirho.serialize_unit(),
            Value::Bool(value_chirho) => serializer_chirho.serialize_bool(*value_chirho),
            Value::Number(value_chirho) => value_chirho.serialize(serializer_chirho),
            Value::String(value_chirho) => serializer_chirho.serialize_str(value_chirho),
            Value::Array(values_chirho) => {
                let mut sequence_chirho =
                    serializer_chirho.serialize_seq(Some(values_chirho.len()))?;
                for value_chirho in values_chirho {
                    sequence_chirho
                        .serialize_element(&CanonicalProjectionJsonValueChirho(value_chirho))?;
                }
                sequence_chirho.end()
            }
            Value::Object(entries_chirho) => {
                // Sort explicitly rather than inheriting serde_json's flippable map backend.
                let mut sorted_entries_chirho = entries_chirho.iter().collect::<Vec<_>>();
                sorted_entries_chirho.sort_unstable_by(|left_chirho, right_chirho| {
                    left_chirho.0.cmp(right_chirho.0)
                });
                let mut map_chirho =
                    serializer_chirho.serialize_map(Some(sorted_entries_chirho.len()))?;
                for (key_chirho, value_chirho) in sorted_entries_chirho {
                    map_chirho.serialize_entry(
                        key_chirho,
                        &CanonicalProjectionJsonValueChirho(value_chirho),
                    )?;
                }
                map_chirho.end()
            }
        }
    }
}

fn canonical_projection_json_value_bytes_chirho(
    value_chirho: &Value,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&CanonicalProjectionJsonValueChirho(value_chirho))
}

/// Serialize any projection DTO with recursively lexicographically sorted object keys.
pub fn canonical_projection_json_bytes_chirho<ValueChirho>(
    value_chirho: &ValueChirho,
) -> Result<Vec<u8>, serde_json::Error>
where
    ValueChirho: Serialize + ?Sized,
{
    let json_value_chirho = serde_json::to_value(value_chirho)?;
    canonical_projection_json_value_bytes_chirho(&json_value_chirho)
}

/// Decode projection JSON only when its bytes already equal the shared canonical encoding.
pub fn parse_canonical_projection_json_value_chirho(
    bytes_chirho: &[u8],
) -> Result<Value, CanonicalProjectionJsonErrorChirho> {
    let value_chirho = serde_json::from_slice(bytes_chirho)
        .map_err(CanonicalProjectionJsonErrorChirho::DecodeChirho)?;
    let canonical_chirho = canonical_projection_json_value_bytes_chirho(&value_chirho)
        .map_err(CanonicalProjectionJsonErrorChirho::EncodeChirho)?;
    if canonical_chirho != bytes_chirho {
        return Err(CanonicalProjectionJsonErrorChirho::NonCanonicalChirho);
    }
    Ok(value_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[derive(Serialize)]
    struct NestedFixtureChirho {
        z_chirho: u64,
        a_chirho: u64,
    }

    #[derive(Serialize)]
    struct ProjectionFixtureChirho {
        z_chirho: u64,
        a_chirho: NestedFixtureChirho,
        list_chirho: Vec<u64>,
    }

    #[test]
    fn canonical_projection_json_sorts_every_object_without_reordering_arrays_chirho() {
        let bytes_chirho = canonical_projection_json_bytes_chirho(&ProjectionFixtureChirho {
            z_chirho: 3,
            a_chirho: NestedFixtureChirho {
                z_chirho: 2,
                a_chirho: 1,
            },
            list_chirho: vec![3, 1, 2],
        })
        .unwrap();
        assert_eq!(
            bytes_chirho,
            br#"{"a_chirho":{"a_chirho":1,"z_chirho":2},"list_chirho":[3,1,2],"z_chirho":3}"#
        );
        assert!(parse_canonical_projection_json_value_chirho(&bytes_chirho).is_ok());
    }

    #[test]
    fn canonical_projection_json_refuses_reordered_whitespace_and_duplicate_keys_chirho() {
        for malformed_chirho in [
            br#"{"z_chirho":3,"a_chirho":1}"#.as_slice(),
            br#"{ "a_chirho":1,"z_chirho":3}"#.as_slice(),
            br#"{"a_chirho":1,"a_chirho":1,"z_chirho":3}"#.as_slice(),
        ] {
            assert!(matches!(
                parse_canonical_projection_json_value_chirho(malformed_chirho),
                Err(CanonicalProjectionJsonErrorChirho::NonCanonicalChirho)
            ));
        }
    }
}
