// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Exact typed projection and canonical materialization over the packet-0 field graph.

use crate::contract_chirho::{
    node_input_projection_binding_hash_chirho, validate_node_input_projection_binding_chirho,
    InputProjectionChirho, NodeInputProjectionBindingChirho,
};
use crate::coordinate_chirho::{
    private_projected_coordinate_chirho, public_projected_coordinate_chirho, PrivateInputKeyChirho,
    ProjectedInputCoordinateChirho,
};
use crate::field_graph_chirho::{
    canonical_field_graph_hash_chirho, field_graph_privacy_class_chirho, CanonicalFieldChirho,
    CanonicalFieldGraphChirho, CanonicalFieldNodeChirho, FieldRequirednessChirho,
    PrivacyClassChirho, ProjectionFieldMetadataPortChirho, CANONICAL_FIELD_GRAPH_SCHEMA_CHIRHO,
};
use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::fmt;

pub struct PrivateCoordinateMaterialChirho<'a> {
    pub key_generation_chirho: &'a str,
    pub key_chirho: &'a PrivateInputKeyChirho,
}

pub struct ProjectionCoordinateContextChirho<'a> {
    pub node_chirho: &'a HashChirho,
    pub port_chirho: &'a str,
    pub private_chirho: Option<PrivateCoordinateMaterialChirho<'a>>,
}

/// One immutable result supplies both coordinate input and eventual runner bytes.
///
/// The bare integrity hash stays private to this boundary. Private callers receive only the keyed
/// coordinate as their cache/audit identifier.
pub struct MaterializedInputChirho {
    pub bytes_chirho: Vec<u8>,
    integrity_hash_chirho: HashChirho,
    pub projected_schema_chirho: CanonicalFieldGraphChirho,
    pub projected_schema_hash_chirho: HashChirho,
    pub source_privacy_class_chirho: PrivacyClassChirho,
    pub projected_privacy_class_chirho: PrivacyClassChirho,
    pub coordinate_chirho: ProjectedInputCoordinateChirho,
}

impl MaterializedInputChirho {
    pub fn verify_integrity_chirho(&self) -> bool {
        self.integrity_hash_chirho.0 == blake3::hash(&self.bytes_chirho).to_hex().to_string()
    }
}

pub fn materialize_exact_node_input_chirho<P: ProjectionFieldMetadataPortChirho + ?Sized>(
    metadata_chirho: &P,
    binding_chirho: &NodeInputProjectionBindingChirho,
    source_bytes_chirho: &[u8],
    coordinate_context_chirho: ProjectionCoordinateContextChirho<'_>,
) -> Result<MaterializedInputChirho> {
    validate_node_input_projection_binding_chirho(binding_chirho)?;
    let source_graph_chirho = metadata_chirho
        .verified_field_graph_chirho(&binding_chirho.source_schema_chirho)
        .context("load verified source field graph")?;
    let actual_source_hash_chirho = canonical_field_graph_hash_chirho(&source_graph_chirho)?;
    if actual_source_hash_chirho != binding_chirho.source_schema_chirho {
        bail!("metadata port returned a field graph outside the requested content address");
    }

    let projected_graph_chirho = match &binding_chirho.projection_chirho {
        InputProjectionChirho::WholeValueChirho => source_graph_chirho.clone(),
        InputProjectionChirho::JsonFieldsChirho {
            consumed_fields_chirho,
        } => derive_projected_field_graph_chirho(&source_graph_chirho, consumed_fields_chirho)?,
    };
    let projected_schema_hash_chirho = canonical_field_graph_hash_chirho(&projected_graph_chirho)?;
    if projected_schema_hash_chirho != binding_chirho.guest_schema_chirho {
        bail!("derived projected schema does not equal the guest schema binding");
    }

    let source_value_chirho = parse_exact_json_value_chirho(source_bytes_chirho)?;
    let mut projected_bytes_chirho = Vec::new();
    validate_source_and_write_projection_chirho(
        &source_graph_chirho.root_chirho,
        Some(&projected_graph_chirho.root_chirho),
        &source_value_chirho,
        &mut projected_bytes_chirho,
    )?;

    let source_privacy_class_chirho = field_graph_privacy_class_chirho(&source_graph_chirho)?;
    let projected_privacy_class_chirho = field_graph_privacy_class_chirho(&projected_graph_chirho)?;
    let private_bearing_chirho = source_privacy_class_chirho != PrivacyClassChirho::SafeChirho
        || projected_privacy_class_chirho != PrivacyClassChirho::SafeChirho;
    let binding_hash_chirho = node_input_projection_binding_hash_chirho(binding_chirho)?;
    let coordinate_chirho = if private_bearing_chirho {
        let private_chirho = coordinate_context_chirho.private_chirho.ok_or_else(|| {
            anyhow::anyhow!("private-bearing input requires one subject-bound coordinate key")
        })?;
        private_projected_coordinate_chirho(
            coordinate_context_chirho.node_chirho,
            coordinate_context_chirho.port_chirho,
            &binding_hash_chirho,
            private_chirho.key_generation_chirho,
            private_chirho.key_chirho,
            &projected_bytes_chirho,
        )?
    } else {
        public_projected_coordinate_chirho(&projected_bytes_chirho)
    };

    Ok(MaterializedInputChirho {
        integrity_hash_chirho: HashChirho(
            blake3::hash(&projected_bytes_chirho).to_hex().to_string(),
        ),
        bytes_chirho: projected_bytes_chirho,
        projected_schema_chirho: projected_graph_chirho,
        projected_schema_hash_chirho,
        source_privacy_class_chirho,
        projected_privacy_class_chirho,
        coordinate_chirho,
    })
}

struct ExactJsonValueChirho(Value);

impl<'de> Deserialize<'de> for ExactJsonValueChirho {
    fn deserialize<D>(deserializer_chirho: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer_chirho.deserialize_any(ExactJsonValueVisitorChirho)
    }
}

struct ExactJsonValueVisitorChirho;

impl<'de> Visitor<'de> for ExactJsonValueVisitorChirho {
    type Value = ExactJsonValueChirho;

    fn expecting(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str("one exact JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value_chirho: bool) -> std::result::Result<ExactJsonValueChirho, E>
    where
        E: de::Error,
    {
        Ok(ExactJsonValueChirho(Value::Bool(value_chirho)))
    }

    fn visit_i64<E>(self, value_chirho: i64) -> std::result::Result<ExactJsonValueChirho, E>
    where
        E: de::Error,
    {
        Ok(ExactJsonValueChirho(Value::Number(value_chirho.into())))
    }

    fn visit_u64<E>(self, value_chirho: u64) -> std::result::Result<ExactJsonValueChirho, E>
    where
        E: de::Error,
    {
        Ok(ExactJsonValueChirho(Value::Number(value_chirho.into())))
    }

    fn visit_f64<E>(self, value_chirho: f64) -> std::result::Result<ExactJsonValueChirho, E>
    where
        E: de::Error,
    {
        let number_chirho = serde_json::Number::from_f64(value_chirho)
            .ok_or_else(|| E::custom("exact JSON number must be finite"))?;
        Ok(ExactJsonValueChirho(Value::Number(number_chirho)))
    }

    fn visit_str<E>(self, value_chirho: &str) -> std::result::Result<ExactJsonValueChirho, E>
    where
        E: de::Error,
    {
        Ok(ExactJsonValueChirho(Value::String(
            value_chirho.to_string(),
        )))
    }

    fn visit_string<E>(self, value_chirho: String) -> std::result::Result<ExactJsonValueChirho, E>
    where
        E: de::Error,
    {
        Ok(ExactJsonValueChirho(Value::String(value_chirho)))
    }

    fn visit_none<E>(self) -> std::result::Result<ExactJsonValueChirho, E>
    where
        E: de::Error,
    {
        Ok(ExactJsonValueChirho(Value::Null))
    }

    fn visit_unit<E>(self) -> std::result::Result<ExactJsonValueChirho, E>
    where
        E: de::Error,
    {
        Ok(ExactJsonValueChirho(Value::Null))
    }

    fn visit_seq<A>(
        self,
        mut sequence_chirho: A,
    ) -> std::result::Result<ExactJsonValueChirho, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values_chirho = Vec::new();
        while let Some(value_chirho) = sequence_chirho.next_element::<ExactJsonValueChirho>()? {
            values_chirho.push(value_chirho.0);
        }
        Ok(ExactJsonValueChirho(Value::Array(values_chirho)))
    }

    fn visit_map<A>(self, mut map_chirho: A) -> std::result::Result<ExactJsonValueChirho, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values_chirho = Map::new();
        while let Some(key_chirho) = map_chirho.next_key::<String>()? {
            if values_chirho.contains_key(&key_chirho) {
                return Err(<A::Error as de::Error>::custom(format!(
                    "exact JSON object contains duplicate key {key_chirho:?}"
                )));
            }
            let value_chirho = map_chirho.next_value::<ExactJsonValueChirho>()?;
            values_chirho.insert(key_chirho, value_chirho.0);
        }
        Ok(ExactJsonValueChirho(Value::Object(values_chirho)))
    }
}

fn parse_exact_json_value_chirho(source_bytes_chirho: &[u8]) -> Result<Value> {
    let mut deserializer_chirho = serde_json::Deserializer::from_slice(source_bytes_chirho);
    let value_chirho = ExactJsonValueChirho::deserialize(&mut deserializer_chirho)
        .context("decode exact node input JSON")?;
    deserializer_chirho
        .end()
        .context("reject trailing bytes after exact node input JSON")?;
    Ok(value_chirho.0)
}

pub fn derive_projected_field_graph_chirho(
    source_graph_chirho: &CanonicalFieldGraphChirho,
    consumed_fields_chirho: &[crate::path_chirho::JsonFieldPathChirho],
) -> Result<CanonicalFieldGraphChirho> {
    crate::field_graph_chirho::validate_canonical_field_graph_chirho(source_graph_chirho)?;
    crate::path_chirho::validate_consumed_fields_chirho(consumed_fields_chirho)?;
    let source_fields_chirho = match &source_graph_chirho.root_chirho {
        CanonicalFieldNodeChirho::ObjectChirho { fields_chirho } => fields_chirho,
        _ => unreachable!("validated field graph has an object root"),
    };
    let path_segments_chirho: Vec<&[String]> = consumed_fields_chirho
        .iter()
        .map(|path_chirho| path_chirho.segments_chirho())
        .collect();
    let fields_chirho = derive_object_fields_chirho(source_fields_chirho, &path_segments_chirho)?;
    Ok(CanonicalFieldGraphChirho {
        schema_chirho: CANONICAL_FIELD_GRAPH_SCHEMA_CHIRHO.to_string(),
        root_chirho: CanonicalFieldNodeChirho::ObjectChirho { fields_chirho },
    })
}

fn derive_object_fields_chirho(
    source_fields_chirho: &[CanonicalFieldChirho],
    paths_chirho: &[&[String]],
) -> Result<Vec<CanonicalFieldChirho>> {
    let mut derived_fields_chirho = Vec::new();
    let mut matched_path_count_chirho = 0_usize;
    for field_chirho in source_fields_chirho {
        let related_chirho: Vec<&[String]> = paths_chirho
            .iter()
            .copied()
            .filter(|segments_chirho| {
                segments_chirho
                    .first()
                    .map(|segment_chirho| segment_chirho == &field_chirho.name_chirho)
                    .unwrap_or(false)
            })
            .collect();
        if related_chirho.is_empty() {
            continue;
        }
        matched_path_count_chirho += related_chirho.len();

        let derived_node_chirho = if related_chirho
            .iter()
            .any(|segments_chirho| segments_chirho.len() == 1)
        {
            if related_chirho.len() != 1 {
                bail!("field selection contains ancestor/descendant overlap");
            }
            field_chirho.node_chirho.clone()
        } else {
            let nested_source_fields_chirho = match &field_chirho.node_chirho {
                CanonicalFieldNodeChirho::ObjectChirho { fields_chirho } => fields_chirho,
                CanonicalFieldNodeChirho::ArrayChirho { .. } => {
                    bail!("v1 field projection cannot traverse an array")
                }
                _ => bail!("field projection path traverses a scalar"),
            };
            let tails_chirho: Vec<&[String]> = related_chirho
                .iter()
                .map(|segments_chirho| &segments_chirho[1..])
                .collect();
            CanonicalFieldNodeChirho::ObjectChirho {
                fields_chirho: derive_object_fields_chirho(
                    nested_source_fields_chirho,
                    &tails_chirho,
                )?,
            }
        };

        let mut derived_field_chirho = field_chirho.clone();
        derived_field_chirho.node_chirho = derived_node_chirho;
        derived_fields_chirho.push(derived_field_chirho);
    }
    if matched_path_count_chirho != paths_chirho.len() {
        bail!("field projection names a path outside the source schema");
    }
    Ok(derived_fields_chirho)
}

fn validate_source_and_write_projection_chirho(
    source_node_chirho: &CanonicalFieldNodeChirho,
    projected_node_chirho: Option<&CanonicalFieldNodeChirho>,
    value_chirho: &Value,
    output_chirho: &mut Vec<u8>,
) -> Result<()> {
    match source_node_chirho {
        CanonicalFieldNodeChirho::ObjectChirho {
            fields_chirho: source_fields_chirho,
        } => {
            let source_object_chirho = value_chirho
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("field-graph object received a non-object value"))?;
            reject_unknown_object_fields_chirho(source_fields_chirho, source_object_chirho)?;
            let projected_fields_chirho = match projected_node_chirho {
                Some(CanonicalFieldNodeChirho::ObjectChirho { fields_chirho }) => {
                    Some(fields_chirho.as_slice())
                }
                Some(_) => bail!("derived projection changed an object's exact type"),
                None => None,
            };

            if projected_fields_chirho.is_some() {
                output_chirho.push(b'{');
            }
            let mut wrote_field_chirho = false;
            for source_field_chirho in source_fields_chirho {
                let selected_field_chirho = projected_fields_chirho.and_then(|fields_chirho| {
                    fields_chirho.iter().find(|field_chirho| {
                        field_chirho.name_chirho == source_field_chirho.name_chirho
                    })
                });
                match source_object_chirho.get(&source_field_chirho.name_chirho) {
                    Some(field_value_chirho) => {
                        if let Some(selected_chirho) = selected_field_chirho {
                            if wrote_field_chirho {
                                output_chirho.push(b',');
                            }
                            write_json_string_chirho(
                                &source_field_chirho.name_chirho,
                                output_chirho,
                            );
                            output_chirho.push(b':');
                            validate_source_and_write_projection_chirho(
                                &source_field_chirho.node_chirho,
                                Some(&selected_chirho.node_chirho),
                                field_value_chirho,
                                output_chirho,
                            )?;
                            wrote_field_chirho = true;
                        } else {
                            validate_source_and_write_projection_chirho(
                                &source_field_chirho.node_chirho,
                                None,
                                field_value_chirho,
                                output_chirho,
                            )?;
                        }
                    }
                    None if source_field_chirho.requiredness_chirho
                        == FieldRequirednessChirho::RequiredChirho =>
                    {
                        bail!("required field is absent from exact node input")
                    }
                    None => {}
                }
            }
            if projected_fields_chirho.is_some() {
                output_chirho.push(b'}');
            }
        }
        CanonicalFieldNodeChirho::ArrayChirho {
            element_chirho: source_element_chirho,
        } => {
            let values_chirho = value_chirho
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("field-graph array received a non-array value"))?;
            let projected_element_chirho = match projected_node_chirho {
                Some(CanonicalFieldNodeChirho::ArrayChirho { element_chirho }) => {
                    Some(element_chirho.as_ref())
                }
                Some(_) => bail!("derived projection changed an array's exact type"),
                None => None,
            };
            if projected_element_chirho.is_some() {
                output_chirho.push(b'[');
            }
            for (index_chirho, element_value_chirho) in values_chirho.iter().enumerate() {
                if projected_element_chirho.is_some() && index_chirho > 0 {
                    output_chirho.push(b',');
                }
                validate_source_and_write_projection_chirho(
                    source_element_chirho,
                    projected_element_chirho,
                    element_value_chirho,
                    output_chirho,
                )?;
            }
            if projected_element_chirho.is_some() {
                output_chirho.push(b']');
            }
        }
        CanonicalFieldNodeChirho::BooleanChirho => {
            if projected_node_chirho.is_some() && projected_node_chirho != Some(source_node_chirho)
            {
                bail!("derived projection changed a boolean's exact type");
            }
            let boolean_chirho = value_chirho
                .as_bool()
                .ok_or_else(|| anyhow::anyhow!("boolean field received a non-boolean value"))?;
            if projected_node_chirho.is_some() {
                output_chirho.extend_from_slice(if boolean_chirho { b"true" } else { b"false" });
            }
        }
        CanonicalFieldNodeChirho::StringChirho => {
            if projected_node_chirho.is_some() && projected_node_chirho != Some(source_node_chirho)
            {
                bail!("derived projection changed a string's exact type");
            }
            let string_chirho = value_chirho
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("string field received a non-string value"))?;
            if projected_node_chirho.is_some() {
                write_json_string_chirho(string_chirho, output_chirho);
            }
        }
        CanonicalFieldNodeChirho::SignedIntegerChirho { bits_chirho } => {
            if projected_node_chirho.is_some() && projected_node_chirho != Some(source_node_chirho)
            {
                bail!("derived projection changed a signed integer's exact type");
            }
            let integer_chirho = validate_signed_integer_chirho(value_chirho, *bits_chirho)?;
            if projected_node_chirho.is_some() {
                output_chirho.extend_from_slice(integer_chirho.to_string().as_bytes());
            }
        }
        CanonicalFieldNodeChirho::UnsignedIntegerChirho { bits_chirho } => {
            if projected_node_chirho.is_some() && projected_node_chirho != Some(source_node_chirho)
            {
                bail!("derived projection changed an unsigned integer's exact type");
            }
            let integer_chirho = validate_unsigned_integer_chirho(value_chirho, *bits_chirho)?;
            if projected_node_chirho.is_some() {
                output_chirho.extend_from_slice(integer_chirho.to_string().as_bytes());
            }
        }
    }
    Ok(())
}

fn reject_unknown_object_fields_chirho(
    fields_chirho: &[CanonicalFieldChirho],
    object_chirho: &Map<String, Value>,
) -> Result<()> {
    for name_chirho in object_chirho.keys() {
        if fields_chirho
            .binary_search_by(|field_chirho| {
                field_chirho
                    .name_chirho
                    .as_bytes()
                    .cmp(name_chirho.as_bytes())
            })
            .is_err()
        {
            bail!("exact node input contains an unknown field");
        }
    }
    Ok(())
}

fn validate_signed_integer_chirho(value_chirho: &Value, bits_chirho: u8) -> Result<i64> {
    let number_chirho = value_chirho
        .as_number()
        .ok_or_else(|| anyhow::anyhow!("signed integer field received a non-number value"))?;
    let integer_chirho = number_chirho
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("signed integer field is not an exact integer"))?;
    if number_chirho.to_string() != integer_chirho.to_string() {
        bail!("signed integer source spelling is noncanonical or lossy");
    }
    let (minimum_chirho, maximum_chirho) = signed_bounds_chirho(bits_chirho)?;
    if integer_chirho < minimum_chirho || integer_chirho > maximum_chirho {
        bail!("signed integer is outside its exact bit width");
    }
    Ok(integer_chirho)
}

fn validate_unsigned_integer_chirho(value_chirho: &Value, bits_chirho: u8) -> Result<u64> {
    let number_chirho = value_chirho
        .as_number()
        .ok_or_else(|| anyhow::anyhow!("unsigned integer field received a non-number value"))?;
    let integer_chirho = number_chirho
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("unsigned integer field is not an exact integer"))?;
    if number_chirho.to_string() != integer_chirho.to_string() {
        bail!("unsigned integer source spelling is noncanonical or lossy");
    }
    let maximum_chirho = unsigned_maximum_chirho(bits_chirho)?;
    if integer_chirho > maximum_chirho {
        bail!("unsigned integer is outside its exact bit width");
    }
    Ok(integer_chirho)
}

fn signed_bounds_chirho(bits_chirho: u8) -> Result<(i64, i64)> {
    match bits_chirho {
        8 => Ok((i8::MIN as i64, i8::MAX as i64)),
        16 => Ok((i16::MIN as i64, i16::MAX as i64)),
        32 => Ok((i32::MIN as i64, i32::MAX as i64)),
        64 => Ok((i64::MIN, i64::MAX)),
        _ => bail!("unsupported signed integer bit width"),
    }
}

fn unsigned_maximum_chirho(bits_chirho: u8) -> Result<u64> {
    match bits_chirho {
        8 => Ok(u8::MAX as u64),
        16 => Ok(u16::MAX as u64),
        32 => Ok(u32::MAX as u64),
        64 => Ok(u64::MAX),
        _ => bail!("unsupported unsigned integer bit width"),
    }
}

fn write_json_string_chirho(value_chirho: &str, output_chirho: &mut Vec<u8>) {
    const HEX_CHIRHO: &[u8; 16] = b"0123456789abcdef";
    output_chirho.push(b'"');
    for char_chirho in value_chirho.chars() {
        match char_chirho {
            '"' => output_chirho.extend_from_slice(br#"\""#),
            '\\' => output_chirho.extend_from_slice(br#"\\"#),
            '\u{0008}' => output_chirho.extend_from_slice(br"\b"),
            '\u{000c}' => output_chirho.extend_from_slice(br"\f"),
            '\n' => output_chirho.extend_from_slice(br"\n"),
            '\r' => output_chirho.extend_from_slice(br"\r"),
            '\t' => output_chirho.extend_from_slice(br"\t"),
            control_chirho if control_chirho <= '\u{001f}' => {
                let byte_chirho = control_chirho as u8;
                output_chirho.extend_from_slice(br"\u00");
                output_chirho.push(HEX_CHIRHO[(byte_chirho >> 4) as usize]);
                output_chirho.push(HEX_CHIRHO[(byte_chirho & 0x0f) as usize]);
            }
            scalar_chirho => {
                let mut buffer_chirho = [0_u8; 4];
                output_chirho
                    .extend_from_slice(scalar_chirho.encode_utf8(&mut buffer_chirho).as_bytes());
            }
        }
    }
    output_chirho.push(b'"');
}
