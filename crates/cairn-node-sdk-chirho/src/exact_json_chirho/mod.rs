// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Generated strict JSON input and canonical WASM attestation macros.

/// Define a JSON input type that rejects unknown fields and has no caller-controlled default.
///
/// Required fields fail on absence. Optional fields distinguish absence from explicit JSON null
/// through `ExactOptionalChirho`; both groups must match the verified projected schema.
#[macro_export]
macro_rules! define_exact_json_input_chirho {
    (
        $visibility_chirho:vis struct $input_chirho:ident {
            required_chirho {
                $(
                    $required_visibility_chirho:vis $required_field_chirho:ident :
                        $required_type_chirho:ty
                ),* $(,)?
            }
            optional_chirho {
                $(
                    $optional_visibility_chirho:vis $optional_field_chirho:ident :
                        $optional_type_chirho:ty
                ),* $(,)?
            }
        }
    ) => {
        #[derive($crate::serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        $visibility_chirho struct $input_chirho {
            $(
                $required_visibility_chirho $required_field_chirho: $required_type_chirho,
            )*
            $(
                #[serde(default)]
                $optional_visibility_chirho $optional_field_chirho:
                    $crate::ExactOptionalChirho<$optional_type_chirho>,
            )*
        }
    };
}

/// Export one strict JSON node and embed its canonical input-schema attestation bytes.
///
/// The payload must be the exact canonical bytes produced by the host-side packet-0 contract. The
/// node-build checker rejects a missing, duplicate, malformed, noncanonical, or mismatched section.
#[macro_export]
macro_rules! export_attested_json_node_chirho {
    (
        $entry_chirho:ident,
        $input_type_chirho:ty,
        $output_type_chirho:ty,
        $handler_chirho:path,
        $attestation_bytes_chirho:literal $(,)?
    ) => {
        const CAIRN_INPUT_SCHEMA_ATTESTATION_BYTES_CHIRHO: &[u8] = $attestation_bytes_chirho;

        #[cfg(target_arch = "wasm32")]
        #[used]
        #[link_section = "cairn-input-schema-chirho"]
        static CAIRN_INPUT_SCHEMA_CUSTOM_SECTION_BYTES_CHIRHO: [u8; $attestation_bytes_chirho
            .len()] = *$attestation_bytes_chirho;

        $crate::export_json_node_chirho!(
            $entry_chirho,
            $input_type_chirho,
            $output_type_chirho,
            $handler_chirho
        );
    };
}

#[cfg(test)]
mod tests_chirho;
