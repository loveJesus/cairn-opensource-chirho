// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Serializable privacy DTOs shared below the root privacy implementation.

use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};

/// The canonical privacy lattice shared by input schemas, read models, and undo contracts.
///
/// Declaration order is load-bearing: derived `Ord` is the privacy order and `max` is its
/// least-upper-bound join. A pure transformation never lowers this value; declassification is a
/// separate reviewed authority path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivacyClassChirho {
    #[serde(rename = "safe-chirho")]
    SafeChirho,
    #[serde(rename = "analytical-chirho")]
    AnalyticalChirho,
    #[serde(rename = "quasi-chirho")]
    QuasiChirho,
    #[serde(rename = "direct-chirho")]
    DirectChirho,
}

/// Least upper bound in the canonical privacy lattice.
pub fn join_privacy_class_chirho(
    left_chirho: PrivacyClassChirho,
    right_chirho: PrivacyClassChirho,
) -> PrivacyClassChirho {
    std::cmp::max(left_chirho, right_chirho)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBlobRefChirho {
    pub ciphertext_chirho: HashChirho,
    pub key_id_chirho: String,
    pub nonce_chirho: String,
    pub mac_chirho: String,
    pub alg_chirho: String,
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn privacy_class_wire_golden_is_stable_chirho() {
        let classes_chirho = [
            PrivacyClassChirho::SafeChirho,
            PrivacyClassChirho::AnalyticalChirho,
            PrivacyClassChirho::QuasiChirho,
            PrivacyClassChirho::DirectChirho,
        ];
        assert_eq!(
            serde_json::to_string(&classes_chirho).unwrap(),
            r#"["safe-chirho","analytical-chirho","quasi-chirho","direct-chirho"]"#
        );
        assert_eq!(
            serde_json::from_str::<[PrivacyClassChirho; 4]>(
                r#"["safe-chirho","analytical-chirho","quasi-chirho","direct-chirho"]"#,
            )
            .unwrap(),
            classes_chirho
        );
    }

    #[test]
    fn privacy_join_truth_table_is_the_lattice_max_chirho() {
        use PrivacyClassChirho::{AnalyticalChirho, DirectChirho, QuasiChirho, SafeChirho};
        let classes_chirho = [SafeChirho, AnalyticalChirho, QuasiChirho, DirectChirho];
        let expected_chirho = [
            [SafeChirho, AnalyticalChirho, QuasiChirho, DirectChirho],
            [
                AnalyticalChirho,
                AnalyticalChirho,
                QuasiChirho,
                DirectChirho,
            ],
            [QuasiChirho, QuasiChirho, QuasiChirho, DirectChirho],
            [DirectChirho, DirectChirho, DirectChirho, DirectChirho],
        ];
        for (left_index_chirho, left_chirho) in classes_chirho.iter().enumerate() {
            for (right_index_chirho, right_chirho) in classes_chirho.iter().enumerate() {
                assert_eq!(
                    join_privacy_class_chirho(*left_chirho, *right_chirho),
                    expected_chirho[left_index_chirho][right_index_chirho],
                    "privacy join drift at ({left_index_chirho}, {right_index_chirho})"
                );
            }
        }
    }

    #[test]
    fn private_blob_ref_serialization_stays_stable_chirho() {
        let ref_chirho = PrivateBlobRefChirho {
            ciphertext_chirho: HashChirho(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
            key_id_chirho: "key-id-chirho".to_string(),
            nonce_chirho: "nonce-chirho".to_string(),
            mac_chirho: "mac-chirho".to_string(),
            alg_chirho: "xchacha20poly1305+blake3-keyed-mac/v1".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&ref_chirho).unwrap(),
            r#"{"ciphertext_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","key_id_chirho":"key-id-chirho","nonce_chirho":"nonce-chirho","mac_chirho":"mac-chirho","alg_chirho":"xchacha20poly1305+blake3-keyed-mac/v1"}"#
        );
    }
}
