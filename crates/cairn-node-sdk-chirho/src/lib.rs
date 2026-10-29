// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Guest-side helpers for Rust WASM nodes that implement cairn's bytes ABI.
//!
//! The v1 bytes ABI is deliberately small: the guest exports `memory`, `alloc_chirho(len) -> ptr`,
//! and one entry function `entry(ptr, len) -> packed`, where `packed = (out_ptr << 32) | out_len`.
//! This crate removes the hand-written WAT boilerplate for pure Rust byte-transform nodes.

#![no_std]

pub extern crate alloc;

#[cfg(feature = "json-chirho")]
pub extern crate serde;

#[cfg(feature = "json-chirho")]
pub extern crate serde_json;

use alloc::vec::Vec;

#[cfg(feature = "json-chirho")]
mod exact_json_chirho;

pub const BYTES_ABI_V1_CHIRHO: &str = "bytes-abi-v1-chirho";
pub const MEMORY_EXPORT_CHIRHO: &str = "memory";
pub const ALLOC_EXPORT_CHIRHO: &str = "alloc_chirho";

/// The canonical in-band "Skipped" stone — mirrors the engine's `model_chirho::SKIPPED_STONE_BYTES_CHIRHO`
/// byte-for-byte. A guest returns these exact bytes from an untaken branch; the runtime then
/// propagates Skipped through pure nodes, logs blessed nodes as skipped-without-invocation, and a
/// `BuiltinPhi` merge ignores it (keeping exactly-one-live). Must stay identical to the engine const.
pub const SKIPPED_STONE_BYTES_CHIRHO: &[u8] =
    br#"{"schema_chirho":"skipped-stone-v1-chirho","skipped_chirho":true}"#;

/// True if `bytes_chirho` is the canonical Skipped stone.
pub fn is_skipped_bytes_chirho(bytes_chirho: &[u8]) -> bool {
    bytes_chirho == SKIPPED_STONE_BYTES_CHIRHO
}

/// The Skipped stone as an owned buffer — what a branch guest returns when its case is untaken.
pub fn skipped_bytes_chirho() -> Vec<u8> {
    SKIPPED_STONE_BYTES_CHIRHO.to_vec()
}

/// Pack a wasm32 pointer and length into the `i64` payload expected by the host.
pub fn pack_ptr_len_chirho(ptr_chirho: u32, len_chirho: u32) -> u64 {
    ((ptr_chirho as u64) << 32) | len_chirho as u64
}

/// Unpack a bytes-ABI result into `(ptr, len)`.
pub fn unpack_ptr_len_chirho(packed_chirho: u64) -> (u32, u32) {
    (
        (packed_chirho >> 32) as u32,
        (packed_chirho & 0xffff_ffff) as u32,
    )
}

/// Allocate a guest buffer for host-written input bytes.
///
/// The buffer is intentionally leaked: a cairn node instance is short-lived, and the host writes
/// into the returned capacity before calling the entry function.
pub fn alloc_guest_buffer_chirho(len_chirho: i32) -> i32 {
    let Ok(len_chirho) = usize::try_from(len_chirho) else {
        return 0;
    };
    let mut buffer_chirho = Vec::<u8>::with_capacity(len_chirho);
    let ptr_chirho = buffer_chirho.as_mut_ptr() as usize;
    core::mem::forget(buffer_chirho);
    ptr_chirho as u32 as i32
}

/// View host-written input bytes in guest memory.
///
/// # Safety
///
/// `ptr_chirho..ptr_chirho+len_chirho` must be a valid initialized range in this module's linear
/// memory. The cairn host satisfies this immediately before calling the exported entry function.
pub unsafe fn input_slice_chirho<'a>(ptr_chirho: i32, len_chirho: i32) -> &'a [u8] {
    let Ok(len_chirho) = usize::try_from(len_chirho) else {
        return &[];
    };
    if len_chirho == 0 {
        return &[];
    }
    let ptr_chirho = ptr_chirho as u32 as usize;
    unsafe { core::slice::from_raw_parts(ptr_chirho as *const u8, len_chirho) }
}

/// Leak output bytes and return the packed bytes-ABI `(ptr, len)` result.
pub fn leak_output_chirho(output_chirho: Vec<u8>) -> i64 {
    if output_chirho.len() > u32::MAX as usize {
        return 0;
    }
    let mut output_chirho = output_chirho.into_boxed_slice();
    let ptr_chirho = output_chirho.as_mut_ptr() as usize;
    if ptr_chirho > u32::MAX as usize {
        return 0;
    }
    let len_chirho = output_chirho.len() as u32;
    core::mem::forget(output_chirho);
    pack_ptr_len_chirho(ptr_chirho as u32, len_chirho) as i64
}

#[cfg(feature = "json-chirho")]
pub fn run_json_handler_chirho<InputChirho, OutputChirho, HandlerChirho>(
    input_chirho: &[u8],
    handler_chirho: HandlerChirho,
) -> Result<Vec<u8>, serde_json::Error>
where
    InputChirho: serde::de::DeserializeOwned,
    OutputChirho: serde::Serialize,
    HandlerChirho: FnOnce(InputChirho) -> OutputChirho,
{
    let input_chirho = serde_json::from_slice::<InputChirho>(input_chirho)?;
    let output_chirho = handler_chirho(input_chirho);
    serde_json::to_vec(&output_chirho)
}

#[cfg(feature = "json-chirho")]
pub fn json_error_bytes_chirho() -> Vec<u8> {
    Vec::from(&b"{\"error_chirho\":\"json-chirho\"}"[..])
}

/// An explicitly optional exact-input field.
///
/// Absence decodes to `None`; a present JSON `null` is rejected so null never masks a missing
/// typed value. The generated exact-input macro uses this wrapper for every optional field.
#[cfg(feature = "json-chirho")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactOptionalChirho<ValueChirho>(Option<ValueChirho>);

#[cfg(feature = "json-chirho")]
impl<ValueChirho> ExactOptionalChirho<ValueChirho> {
    pub fn as_ref_chirho(&self) -> Option<&ValueChirho> {
        self.0.as_ref()
    }

    pub fn into_option_chirho(self) -> Option<ValueChirho> {
        self.0
    }
}

#[cfg(feature = "json-chirho")]
impl<ValueChirho> Default for ExactOptionalChirho<ValueChirho> {
    fn default() -> Self {
        Self(None)
    }
}

#[cfg(feature = "json-chirho")]
impl<'de, ValueChirho> serde::Deserialize<'de> for ExactOptionalChirho<ValueChirho>
where
    ValueChirho: serde::de::DeserializeOwned,
{
    fn deserialize<DeserializerChirho>(
        deserializer_chirho: DeserializerChirho,
    ) -> Result<Self, DeserializerChirho::Error>
    where
        DeserializerChirho: serde::Deserializer<'de>,
    {
        let value_chirho =
            <serde_json::Value as serde::Deserialize>::deserialize(deserializer_chirho)?;
        if value_chirho.is_null() {
            return Err(<DeserializerChirho::Error as serde::de::Error>::custom(
                "explicit null is not a valid exact optional input",
            ));
        }
        serde_json::from_value(value_chirho)
            .map(|value_chirho| Self(Some(value_chirho)))
            .map_err(<DeserializerChirho::Error as serde::de::Error>::custom)
    }
}

/// Export one pure bytes node under cairn's v1 bytes ABI.
///
/// The handler must have the shape `fn(&[u8]) -> Vec<u8>`. v1 intentionally exports one node per
/// guest module, so the macro also exports the shared `alloc_chirho` function.
#[macro_export]
macro_rules! export_bytes_node_chirho {
    ($entry_chirho:ident, $handler_chirho:path) => {
        #[no_mangle]
        pub extern "C" fn alloc_chirho(len_chirho: i32) -> i32 {
            $crate::alloc_guest_buffer_chirho(len_chirho)
        }

        #[no_mangle]
        pub unsafe extern "C" fn $entry_chirho(ptr_chirho: i32, len_chirho: i32) -> i64 {
            let input_chirho = unsafe { $crate::input_slice_chirho(ptr_chirho, len_chirho) };
            let output_chirho = $handler_chirho(input_chirho);
            $crate::leak_output_chirho(output_chirho)
        }
    };
}

/// Export one typed JSON node under cairn's v1 bytes ABI.
///
/// The handler must have the shape `fn(InputChirho) -> OutputChirho`, where input implements
/// `DeserializeOwned` and output implements `Serialize`. The raw bytes crossing the host boundary
/// remain the existing bytes ABI; this macro only handles JSON decode/encode inside the guest.
#[cfg(feature = "json-chirho")]
#[macro_export]
macro_rules! export_json_node_chirho {
    ($entry_chirho:ident, $input_ty_chirho:ty, $output_ty_chirho:ty, $handler_chirho:path) => {
        #[no_mangle]
        pub extern "C" fn alloc_chirho(len_chirho: i32) -> i32 {
            $crate::alloc_guest_buffer_chirho(len_chirho)
        }

        #[no_mangle]
        pub unsafe extern "C" fn $entry_chirho(ptr_chirho: i32, len_chirho: i32) -> i64 {
            let input_chirho = unsafe { $crate::input_slice_chirho(ptr_chirho, len_chirho) };
            let output_chirho =
                match $crate::run_json_handler_chirho::<$input_ty_chirho, $output_ty_chirho, _>(
                    input_chirho,
                    $handler_chirho,
                ) {
                    Ok(bytes_chirho) => bytes_chirho,
                    Err(_error_chirho) => $crate::json_error_bytes_chirho(),
                };
            $crate::leak_output_chirho(output_chirho)
        }
    };
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn pack_unpack_round_trips_chirho() {
        let packed_chirho = pack_ptr_len_chirho(0x89ab_cdef, 0x0123_4567);
        assert_eq!(
            unpack_ptr_len_chirho(packed_chirho),
            (0x89ab_cdef, 0x0123_4567)
        );
    }

    #[test]
    fn negative_alloc_len_refuses_chirho() {
        assert_eq!(alloc_guest_buffer_chirho(-1), 0);
    }

    #[test]
    fn zero_len_input_is_empty_chirho() {
        let input_chirho = unsafe { input_slice_chirho(1024, 0) };
        assert!(input_chirho.is_empty());
    }

    #[cfg(feature = "json-chirho")]
    #[test]
    fn json_handler_round_trips_chirho() {
        #[derive(serde::Deserialize)]
        struct InputChirho {
            name_chirho: alloc::string::String,
        }

        #[derive(serde::Serialize)]
        struct OutputChirho {
            message_chirho: alloc::string::String,
        }

        fn greet_chirho(input_chirho: InputChirho) -> OutputChirho {
            OutputChirho {
                message_chirho: alloc::format!("Hello, {}", input_chirho.name_chirho),
            }
        }

        let output_chirho = run_json_handler_chirho::<InputChirho, OutputChirho, _>(
            br#"{"name_chirho":"L.J."}"#,
            greet_chirho,
        )
        .unwrap();
        assert_eq!(output_chirho, br#"{"message_chirho":"Hello, L.J."}"#);
    }
}
