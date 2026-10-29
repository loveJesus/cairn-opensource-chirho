// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Shared canonical wire codec: lowercase hex for fixed byte arrays, compact serde-json for whole
//! records, and the newtype macros every geo-genesis scalar and digest is stamped from. One canonical
//! form per value is the whole point — an uppercase digit or an odd length is refused, not tolerated.

use crate::error_chirho::{GeoGenesisRefusalChirho, GeoGenesisResultChirho};

/// Lowercase hex of a fixed byte slice.
pub(crate) fn encode_lower_hex_chirho(bytes_chirho: &[u8]) -> String {
    let mut out_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        out_chirho.push(nibble_to_hex_chirho(byte_chirho >> 4));
        out_chirho.push(nibble_to_hex_chirho(byte_chirho & 0x0f));
    }
    out_chirho
}

fn nibble_to_hex_chirho(nibble_chirho: u8) -> char {
    match nibble_chirho {
        0..=9 => (b'0' + nibble_chirho) as char,
        _ => (b'a' + nibble_chirho - 10) as char,
    }
}

fn hex_nibble_chirho(byte_chirho: u8) -> Option<u8> {
    match byte_chirho {
        b'0'..=b'9' => Some(byte_chirho - b'0'),
        b'a'..=b'f' => Some(byte_chirho - b'a' + 10),
        _ => None,
    }
}

/// Decode exactly `2*N` lowercase hex characters into `[u8; N]`; wrong length, uppercase, or any
/// non-hex byte refuses so the wire form is canonical.
pub(crate) fn decode_lower_hex_array_chirho<const N: usize>(
    value_chirho: &str,
) -> GeoGenesisResultChirho<[u8; N]> {
    let bytes_chirho = value_chirho.as_bytes();
    if bytes_chirho.len() != N * 2 {
        return Err(GeoGenesisRefusalChirho::HexEncodingChirho);
    }
    let mut out_chirho = [0u8; N];
    for (index_chirho, out_byte_chirho) in out_chirho.iter_mut().enumerate() {
        let high_chirho = hex_nibble_chirho(bytes_chirho[index_chirho * 2])
            .ok_or(GeoGenesisRefusalChirho::HexEncodingChirho)?;
        let low_chirho = hex_nibble_chirho(bytes_chirho[index_chirho * 2 + 1])
            .ok_or(GeoGenesisRefusalChirho::HexEncodingChirho)?;
        *out_byte_chirho = (high_chirho << 4) | low_chirho;
    }
    Ok(out_chirho)
}

/// Blake3 hex of canonical bytes; the shared identity helper the higher records reuse. This computes
/// a digest of bytes handed in; it does not reload, verify, or bind any external artifact (8.2b).
pub fn canonical_blake3_hex_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

/// Fixed upper bound on any candidate record's byte length, checked before a parse is attempted.
pub(crate) const MAX_GEO_RECORD_BYTES_CHIRHO: usize = 256 * 1024;

/// Compact canonical bytes of any serde value; struct field order is the canonical JSON order.
pub(crate) fn canonical_record_bytes_chirho<ValueChirho: serde::Serialize>(
    value_chirho: &ValueChirho,
) -> GeoGenesisResultChirho<Vec<u8>> {
    serde_json::to_vec(value_chirho)
        .map_err(|_error_chirho| GeoGenesisRefusalChirho::MalformedChirho)
}

/// Parse candidate bytes into a record, enforcing the size bound, unknown/duplicate-field refusal
/// (through the record's own serde derives), and an exact canonical round-trip. Semantic validation
/// is the caller's job — this fixes only the wire law, not the meaning.
pub(crate) fn parse_canonical_chirho<ValueChirho>(
    bytes_chirho: &[u8],
) -> GeoGenesisResultChirho<ValueChirho>
where
    ValueChirho: serde::Serialize + serde::de::DeserializeOwned,
{
    if bytes_chirho.len() > MAX_GEO_RECORD_BYTES_CHIRHO {
        return Err(GeoGenesisRefusalChirho::TooLargeChirho);
    }
    let value_chirho: ValueChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_error_chirho| GeoGenesisRefusalChirho::MalformedChirho)?;
    let canonical_chirho = canonical_record_bytes_chirho(&value_chirho)?;
    if canonical_chirho != bytes_chirho {
        return Err(GeoGenesisRefusalChirho::NotCanonicalChirho);
    }
    Ok(value_chirho)
}

/// Stamp one opaque, validated, distinct fixed-hex newtype: private inner array, a validating
/// constructor, a lowercase-hex wire codec, and a hex `Debug`. Each invocation is its own type, so
/// one evidence/key class can never be passed where another is expected.
macro_rules! geo_hex_newtype_chirho {
    ($(#[$doc:meta])* $name:ident, $len:literal, reject_zero) => {
        $crate::codec_chirho::geo_hex_newtype_body_chirho!($(#[$doc])* $name, $len, true);
    };
    ($(#[$doc:meta])* $name:ident, $len:literal) => {
        $crate::codec_chirho::geo_hex_newtype_body_chirho!($(#[$doc])* $name, $len, false);
    };
}

macro_rules! geo_hex_newtype_body_chirho {
    ($(#[$doc:meta])* $name:ident, $len:literal, $reject_zero:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Construct from raw bytes, refusing the all-zero identity when this class requires it.
            pub fn new_chirho(
                bytes_chirho: [u8; $len],
            ) -> $crate::error_chirho::GeoGenesisResultChirho<Self> {
                if $reject_zero && bytes_chirho.iter().all(|byte_chirho| *byte_chirho == 0) {
                    return Err($crate::error_chirho::GeoGenesisRefusalChirho::AllZeroIdentityChirho);
                }
                Ok(Self(bytes_chirho))
            }

            /// Parse from the lowercase-hex wire form.
            pub fn from_hex_chirho(
                value_chirho: &str,
            ) -> $crate::error_chirho::GeoGenesisResultChirho<Self> {
                let bytes_chirho =
                    $crate::codec_chirho::decode_lower_hex_array_chirho::<$len>(value_chirho)?;
                Self::new_chirho(bytes_chirho)
            }

            /// Borrow the fixed bytes.
            pub fn as_bytes_chirho(&self) -> &[u8; $len] {
                &self.0
            }

            /// Lowercase-hex wire form.
            pub fn to_hex_chirho(&self) -> String {
                $crate::codec_chirho::encode_lower_hex_chirho(&self.0)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, formatter_chirho: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(formatter_chirho, "{}({})", stringify!($name), self.to_hex_chirho())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<SerializerChirho: serde::Serializer>(
                &self,
                serializer_chirho: SerializerChirho,
            ) -> Result<SerializerChirho::Ok, SerializerChirho::Error> {
                serializer_chirho.serialize_str(&self.to_hex_chirho())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<DeserializerChirho: serde::Deserializer<'de>>(
                deserializer_chirho: DeserializerChirho,
            ) -> Result<Self, DeserializerChirho::Error> {
                let raw_chirho = String::deserialize(deserializer_chirho)?;
                Self::from_hex_chirho(&raw_chirho).map_err(serde::de::Error::custom)
            }
        }
    };
}

/// Stamp one opaque, validated numeric coordinate newtype with an integer wire form. The `nonzero`
/// form refuses zero with the named reason; the plain form admits any value in the integer's range.
macro_rules! geo_uint_newtype_chirho {
    ($(#[$doc:meta])* $name:ident, $inner:ty, nonzero $err:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name($inner);

        impl $name {
            /// Construct, refusing zero.
            pub fn new_chirho(
                value_chirho: $inner,
            ) -> $crate::error_chirho::GeoGenesisResultChirho<Self> {
                if value_chirho == 0 {
                    return Err($crate::error_chirho::GeoGenesisRefusalChirho::$err);
                }
                Ok(Self(value_chirho))
            }

            /// The numeric coordinate.
            pub fn get_chirho(&self) -> $inner {
                self.0
            }
        }

        $crate::codec_chirho::geo_uint_serde_chirho!($name, $inner);
    };
    ($(#[$doc:meta])* $name:ident, $inner:ty) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name($inner);

        impl $name {
            /// Construct; every value in range is admitted.
            pub fn new_chirho(
                value_chirho: $inner,
            ) -> $crate::error_chirho::GeoGenesisResultChirho<Self> {
                Ok(Self(value_chirho))
            }

            /// The numeric coordinate.
            pub fn get_chirho(&self) -> $inner {
                self.0
            }
        }

        $crate::codec_chirho::geo_uint_serde_chirho!($name, $inner);
    };
}

macro_rules! geo_uint_serde_chirho {
    ($name:ident, $inner:ty) => {
        impl serde::Serialize for $name {
            fn serialize<SerializerChirho: serde::Serializer>(
                &self,
                serializer_chirho: SerializerChirho,
            ) -> Result<SerializerChirho::Ok, SerializerChirho::Error> {
                self.0.serialize(serializer_chirho)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<DeserializerChirho: serde::Deserializer<'de>>(
                deserializer_chirho: DeserializerChirho,
            ) -> Result<Self, DeserializerChirho::Error> {
                let value_chirho = <$inner>::deserialize(deserializer_chirho)?;
                Self::new_chirho(value_chirho).map_err(serde::de::Error::custom)
            }
        }
    };
}

pub(crate) use geo_hex_newtype_body_chirho;
pub(crate) use geo_hex_newtype_chirho;
pub(crate) use geo_uint_newtype_chirho;
pub(crate) use geo_uint_serde_chirho;
