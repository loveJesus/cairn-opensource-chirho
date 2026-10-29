// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The canonical checked-DAG asset-operation value.
//!
//! Operation identity is deliberately absent: the descriptor-v2 door names mint, burn, transfer,
//! or another reviewed money operation. This payload carries only the value coordinate shared by
//! those doors. Rounding controls a derivation; it is never permission to create or destroy value.
//! The ledger record's balanced-leg law remains the conservation authority, and each ledger
//! operation retains its own zero-amount admission law.

use crate::ids_chirho::{AssetKindIdChirho, AssetKindRefChirho, DigestChirho};
use serde::{Deserialize, Serialize};

/// Literal review pin for the content address returned by
/// [`asset_op_field_graph_digest_chirho`]. Regenerate only as an explicit schema migration.
pub const ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO: &str =
    "543af9c70df3d8684c97e1037559afae3225eebaa78161b0d5c1a411beead990";

/// One canonical packet-0 field graph for every checked money door.
///
/// Ledger-model owns these bytes without depending upward on the projection/checker crate. The
/// integration layer parses them through `CanonicalFieldGraphChirho` and exact-resolves this
/// content address; it never defines a parallel schema. Amount is analytical financial data while
/// the stable kind, immutable policy reference, and rounding coordinate are safe metadata.
pub const ASSET_OP_FIELD_GRAPH_SCHEMA_V1_CHIRHO: &str = concat!(
    r#"{"schema_chirho":"canonical-field-graph-v1-chirho","root_chirho":{"kind_chirho":"object-chirho","fields_chirho":["#,
    r#"{"name_chirho":"amount_chirho","node_chirho":{"kind_chirho":"unsigned-integer-chirho","bits_chirho":64},"requiredness_chirho":"required-chirho","variability_chirho":"invocation-varying-chirho","privacy_class_chirho":"analytical-chirho","indexed_chirho":false},"#,
    r#"{"name_chirho":"kind_id_chirho","node_chirho":{"kind_chirho":"string-chirho"},"requiredness_chirho":"required-chirho","variability_chirho":"invocation-varying-chirho","privacy_class_chirho":"safe-chirho","indexed_chirho":false},"#,
    r#"{"name_chirho":"kind_policy_ref_chirho","node_chirho":{"kind_chirho":"string-chirho"},"requiredness_chirho":"required-chirho","variability_chirho":"invocation-varying-chirho","privacy_class_chirho":"safe-chirho","indexed_chirho":false},"#,
    r#"{"name_chirho":"rounding_chirho","node_chirho":{"kind_chirho":"string-chirho"},"requiredness_chirho":"required-chirho","variability_chirho":"invocation-varying-chirho","privacy_class_chirho":"safe-chirho","indexed_chirho":false}]}}"#,
);

/// An explicit closed rounding law. No implicit/default mode exists on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RoundingChirho {
    /// The derivation must already be an exact integer; any remainder refuses.
    #[serde(rename = "exact-chirho")]
    ExactChirho,
    /// Round an unsigned derivation toward zero (equivalently, floor).
    #[serde(rename = "down-chirho")]
    DownChirho,
    /// Round an unsigned derivation away from zero (equivalently, ceiling).
    #[serde(rename = "up-chirho")]
    UpChirho,
    /// Round to the nearest integer, resolving an exact tie to the even integer.
    #[serde(rename = "nearest-ties-to-even-chirho")]
    NearestTiesToEvenChirho,
}

/// The only value shape a checked money door may consume.
///
/// Amount is an unsigned integer in the asset kind's minor unit. A zero amount parses normally;
/// transfer/mint/burn admission decides whether zero is legal for that operation. There is no
/// operation enum or sign field: direction and operation identity remain in the reviewed door and
/// balanced ledger legs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetOpChirho {
    pub amount_chirho: u64,
    pub kind_id_chirho: AssetKindIdChirho,
    pub kind_policy_ref_chirho: AssetKindRefChirho,
    pub rounding_chirho: RoundingChirho,
}

/// Why an AssetOp wire value was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssetOpWireErrorChirho {
    /// Malformed JSON, unknown/duplicate/missing fields, or a wrong scalar/enum type.
    MalformedChirho { detail_chirho: String },
    /// Typed parse succeeded, but exact canonical reserialization differs byte-for-byte.
    NonCanonicalBytesChirho,
    /// Serialization failed before canonical bytes could be emitted.
    SerializeChirho { detail_chirho: String },
}

impl std::fmt::Display for AssetOpWireErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedChirho { detail_chirho } => {
                write!(formatter_chirho, "malformed AssetOp: {detail_chirho}")
            }
            Self::NonCanonicalBytesChirho => {
                write!(formatter_chirho, "AssetOp bytes are not canonical")
            }
            Self::SerializeChirho { detail_chirho } => {
                write!(formatter_chirho, "serialize AssetOp: {detail_chirho}")
            }
        }
    }
}

impl std::error::Error for AssetOpWireErrorChirho {}

/// Why a money door's declared rounding policy refused an otherwise canonical AssetOp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetOpRoundingErrorChirho {
    PlainMoveRequiresExactChirho {
        found_chirho: RoundingChirho,
    },
    KindPolicyMismatchChirho {
        found_chirho: RoundingChirho,
        policy_chirho: RoundingChirho,
    },
}

impl std::fmt::Display for AssetOpRoundingErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PlainMoveRequiresExactChirho { found_chirho } => write!(
                formatter_chirho,
                "plain asset move requires exact rounding, found {found_chirho:?}"
            ),
            Self::KindPolicyMismatchChirho {
                found_chirho,
                policy_chirho,
            } => write!(
                formatter_chirho,
                "asset derivation rounding {found_chirho:?} does not match kind policy {policy_chirho:?}"
            ),
        }
    }
}

impl std::error::Error for AssetOpRoundingErrorChirho {}

impl AssetOpChirho {
    /// A plain move has no derivation remainder and therefore must declare exact rounding.
    pub fn validate_plain_move_rounding_chirho(&self) -> Result<(), AssetOpRoundingErrorChirho> {
        if self.rounding_chirho == RoundingChirho::ExactChirho {
            Ok(())
        } else {
            Err(AssetOpRoundingErrorChirho::PlainMoveRequiresExactChirho {
                found_chirho: self.rounding_chirho,
            })
        }
    }

    /// A derived value may remain exact or use exactly the immutable kind-policy rounding rule.
    pub fn validate_derived_rounding_chirho(
        &self,
        policy_chirho: RoundingChirho,
    ) -> Result<(), AssetOpRoundingErrorChirho> {
        if self.rounding_chirho == RoundingChirho::ExactChirho
            || self.rounding_chirho == policy_chirho
        {
            Ok(())
        } else {
            Err(AssetOpRoundingErrorChirho::KindPolicyMismatchChirho {
                found_chirho: self.rounding_chirho,
                policy_chirho,
            })
        }
    }
}

/// Emit the only canonical JSON bytes for one AssetOp value.
pub fn canonical_asset_op_bytes_chirho(
    asset_op_chirho: &AssetOpChirho,
) -> Result<Vec<u8>, AssetOpWireErrorChirho> {
    serde_json::to_vec(asset_op_chirho).map_err(|error_chirho| {
        AssetOpWireErrorChirho::SerializeChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })
}

/// Strict typed parse followed by exact byte reserialization.
///
/// This refuses parser normalization, including field reorder, whitespace, and trailing bytes, so
/// one logical operation cannot acquire multiple content identities.
pub fn parse_canonical_asset_op_chirho(
    bytes_chirho: &[u8],
) -> Result<AssetOpChirho, AssetOpWireErrorChirho> {
    let asset_op_chirho: AssetOpChirho =
        serde_json::from_slice(bytes_chirho).map_err(|error_chirho| {
            AssetOpWireErrorChirho::MalformedChirho {
                detail_chirho: error_chirho.to_string(),
            }
        })?;
    if canonical_asset_op_bytes_chirho(&asset_op_chirho)? != bytes_chirho {
        return Err(AssetOpWireErrorChirho::NonCanonicalBytesChirho);
    }
    Ok(asset_op_chirho)
}

/// Content address of the one ledger-owned AssetOp packet-0 field graph.
pub fn asset_op_field_graph_digest_chirho() -> DigestChirho {
    DigestChirho(
        blake3::hash(ASSET_OP_FIELD_GRAPH_SCHEMA_V1_CHIRHO.as_bytes())
            .to_hex()
            .to_string(),
    )
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    const GOLDEN_ASSET_OP_BYTES_CHIRHO: &str = r#"{"amount_chirho":125,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"nearest-ties-to-even-chirho"}"#;

    fn golden_asset_op_chirho() -> AssetOpChirho {
        AssetOpChirho {
            amount_chirho: 125,
            kind_id_chirho: AssetKindIdChirho("usd-chirho".to_owned()),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                "policy-v1-digest-chirho".to_owned(),
            )),
            rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
        }
    }

    fn assert_malformed_chirho(wire_chirho: &str) {
        assert!(matches!(
            parse_canonical_asset_op_chirho(wire_chirho.as_bytes()),
            Err(AssetOpWireErrorChirho::MalformedChirho { .. })
        ));
    }

    #[test]
    fn golden_asset_op_bytes_and_schema_digest_are_stable_chirho() {
        let asset_op_chirho = golden_asset_op_chirho();
        assert_eq!(
            canonical_asset_op_bytes_chirho(&asset_op_chirho).unwrap(),
            GOLDEN_ASSET_OP_BYTES_CHIRHO.as_bytes()
        );
        assert_eq!(
            parse_canonical_asset_op_chirho(GOLDEN_ASSET_OP_BYTES_CHIRHO.as_bytes()).unwrap(),
            asset_op_chirho
        );
        assert_eq!(
            asset_op_field_graph_digest_chirho().0,
            ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO
        );
    }

    #[test]
    #[ignore = "generator: prints the reviewed AssetOp schema digest candidate"]
    fn print_asset_op_schema_digest_chirho() {
        println!("{}", asset_op_field_graph_digest_chirho().0);
    }

    #[test]
    fn wrong_amount_shapes_and_missing_or_unknown_rounding_refuse_chirho() {
        for wire_chirho in [
            r#"{"amount_chirho":1.0,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"exact-chirho"}"#,
            r#"{"amount_chirho":1.5,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"exact-chirho"}"#,
            r#"{"amount_chirho":1e2,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"exact-chirho"}"#,
            r#"{"amount_chirho":-1,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"exact-chirho"}"#,
            r#"{"amount_chirho":"1","kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"exact-chirho"}"#,
            r#"{"amount_chirho":1,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho"}"#,
            r#"{"amount_chirho":1,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"ties-away-chirho"}"#,
        ] {
            assert_malformed_chirho(wire_chirho);
        }
    }

    #[test]
    fn unknown_duplicate_and_operation_fields_refuse_chirho() {
        assert_malformed_chirho(
            r#"{"amount_chirho":1,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"exact-chirho","extra_chirho":true}"#,
        );
        assert_malformed_chirho(
            r#"{"amount_chirho":1,"amount_chirho":2,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"exact-chirho"}"#,
        );
        assert_malformed_chirho(
            r#"{"amount_chirho":1,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"exact-chirho","operation_chirho":"mint-chirho"}"#,
        );
    }

    #[test]
    fn reordered_whitespace_and_trailing_encodings_refuse_chirho() {
        for wire_chirho in [
            r#"{"kind_id_chirho":"usd-chirho","amount_chirho":125,"kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"nearest-ties-to-even-chirho"}"#,
            r#"{ "amount_chirho":125,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"nearest-ties-to-even-chirho"}"#,
            concat!(
                r#"{"amount_chirho":125,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"nearest-ties-to-even-chirho"}"#,
                "\n"
            ),
        ] {
            assert_eq!(
                parse_canonical_asset_op_chirho(wire_chirho.as_bytes()),
                Err(AssetOpWireErrorChirho::NonCanonicalBytesChirho)
            );
        }
        assert_malformed_chirho(&format!("{GOLDEN_ASSET_OP_BYTES_CHIRHO}x"));
    }

    #[test]
    fn zero_parses_without_overriding_ledger_operation_law_chirho() {
        let zero_chirho = r#"{"amount_chirho":0,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"exact-chirho"}"#;
        assert_eq!(
            parse_canonical_asset_op_chirho(zero_chirho.as_bytes())
                .unwrap()
                .amount_chirho,
            0
        );
    }

    #[test]
    fn rounding_policy_is_exact_or_exactly_kind_attested_chirho() {
        let mut asset_op_chirho = golden_asset_op_chirho();
        assert_eq!(
            asset_op_chirho.validate_plain_move_rounding_chirho(),
            Err(AssetOpRoundingErrorChirho::PlainMoveRequiresExactChirho {
                found_chirho: RoundingChirho::NearestTiesToEvenChirho,
            })
        );
        assert!(asset_op_chirho
            .validate_derived_rounding_chirho(RoundingChirho::NearestTiesToEvenChirho)
            .is_ok());
        assert_eq!(
            asset_op_chirho.validate_derived_rounding_chirho(RoundingChirho::DownChirho),
            Err(AssetOpRoundingErrorChirho::KindPolicyMismatchChirho {
                found_chirho: RoundingChirho::NearestTiesToEvenChirho,
                policy_chirho: RoundingChirho::DownChirho,
            })
        );
        asset_op_chirho.rounding_chirho = RoundingChirho::ExactChirho;
        assert!(asset_op_chirho
            .validate_plain_move_rounding_chirho()
            .is_ok());
        assert!(asset_op_chirho
            .validate_derived_rounding_chirho(RoundingChirho::UpChirho)
            .is_ok());
    }
}
