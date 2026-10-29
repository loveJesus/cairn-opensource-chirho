// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The self-verifying finality proof (§11.8a, CF2 F3a — signed #5038/#5044/#5045/#5046): a
//! root-signed, content-addressed statement that a specific source burn is an ANCESTOR of a
//! typed retained cut. Destination verification is implemented; production source issuance remains
//! deliberately absent until one verified snapshot binds the exact burn and retained-cut witnesses.

use crate::counterpart_chirho::{CounterpartClaimChirho, FinalBurnRefChirho};
use crate::ids_chirho::{
    AccountIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho, MoneyGroupIdChirho,
    SettlementChannelIdChirho,
};
use crate::wire_chirho::WireErrorChirho;
use crate::ShardEpochChirho;
use serde::{Deserialize, Serialize};

/// The finality-proof family's schema tag (proof ≠ record ≠ saga ≠ registry).
pub const FINALITY_PROOF_SCHEMA_V1_CHIRHO: &str = "ledger-finality-proof-v1-chirho";

/// The TYPED retained-cut identity (gpt C1): epoch + seq + stored record digest — never a bare
/// number, so two forks sharing a seq are distinguishable and the proof names ONE real chain cut.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedCutChirho {
    pub cut_epoch_chirho: ShardEpochChirho,
    pub cut_seq_chirho: u64,
    pub cut_record_digest_chirho: DigestChirho,
}

/// The proof: source locator (byte-equal to the claim's `FinalBurnRefChirho` minus the proof ref),
/// the retained cut it proves ancestry into, and the BOUND burn summary the destination equality-
/// checks against the claim and its legs (law i — bound, never merely referenced).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalityProofChirho {
    pub schema_chirho: String,
    pub source_money_group_chirho: MoneyGroupIdChirho,
    pub source_cluster_chirho: ClusterIdChirho,
    pub source_epoch_chirho: ShardEpochChirho,
    pub source_seq_chirho: u64,
    pub source_record_digest_chirho: DigestChirho,
    pub cut_chirho: RetainedCutChirho,
    pub burn_amount_chirho: u64,
    pub burn_kind_policy_ref_chirho: AssetKindRefChirho,
    pub burn_src_chirho: AccountIdChirho,
    pub burn_dst_money_group_chirho: MoneyGroupIdChirho,
    pub burn_dst_cluster_chirho: ClusterIdChirho,
    pub burn_dst_chirho: AccountIdChirho,
    pub burn_channel_chirho: SettlementChannelIdChirho,
    pub root_sig_chirho: String,
}

/// Canonical line: validate (schema + the cut law `cut_seq >= source_seq` — a proof claiming a
/// cut BEFORE the burn is nonsense and refuses at emit AND parse) then the ONE serde emission.
pub fn canonical_finality_proof_line_chirho(
    proof_chirho: &FinalityProofChirho,
) -> Result<String, WireErrorChirho> {
    if proof_chirho.schema_chirho != FINALITY_PROOF_SCHEMA_V1_CHIRHO {
        return Err(WireErrorChirho::SchemaMismatchChirho {
            found_chirho: proof_chirho.schema_chirho.clone(),
        });
    }
    if proof_chirho.cut_chirho.cut_seq_chirho < proof_chirho.source_seq_chirho {
        return Err(WireErrorChirho::MalformedChirho {
            detail_chirho: "finality proof cut precedes the burn (cut law)".to_owned(),
        });
    }
    serde_json::to_string(proof_chirho).map_err(|error_chirho| WireErrorChirho::SerializeChirho {
        detail_chirho: error_chirho.to_string(),
    })
}

/// Strict parse: schema probe, typed decode, the cut law, exact reserialize-byte equality.
pub fn parse_canonical_finality_proof_line_chirho(
    line_chirho: &str,
) -> Result<FinalityProofChirho, WireErrorChirho> {
    #[derive(Deserialize)]
    struct SchemaProbeChirho {
        schema_chirho: String,
    }
    let probe_chirho: SchemaProbeChirho =
        serde_json::from_str(line_chirho).map_err(|error_chirho| {
            WireErrorChirho::MalformedChirho {
                detail_chirho: format!("probe finality proof schema: {error_chirho}"),
            }
        })?;
    if probe_chirho.schema_chirho != FINALITY_PROOF_SCHEMA_V1_CHIRHO {
        return Err(WireErrorChirho::SchemaMismatchChirho {
            found_chirho: probe_chirho.schema_chirho,
        });
    }
    let proof_chirho: FinalityProofChirho =
        serde_json::from_str(line_chirho).map_err(|error_chirho| {
            WireErrorChirho::MalformedChirho {
                detail_chirho: format!("decode finality proof: {error_chirho}"),
            }
        })?;
    let canonical_chirho = canonical_finality_proof_line_chirho(&proof_chirho)?;
    if canonical_chirho != line_chirho {
        return Err(WireErrorChirho::NonCanonicalBytesChirho);
    }
    Ok(proof_chirho)
}

/// The root-signed content: the canonical line with the signature blanked (sign-then-attach).
pub fn finality_proof_signed_content_chirho(
    proof_chirho: &FinalityProofChirho,
) -> Result<String, WireErrorChirho> {
    let mut unsigned_chirho = proof_chirho.clone();
    unsigned_chirho.root_sig_chirho = String::new();
    canonical_finality_proof_line_chirho(&unsigned_chirho)
}

/// The content address the claim's `finality_proof_ref` must equal: blake3 of the FULL canonical
/// line (signature included — the ref binds one specific signed proof instance).
pub fn derive_finality_proof_ref_chirho(
    proof_chirho: &FinalityProofChirho,
) -> Result<DigestChirho, WireErrorChirho> {
    let line_chirho = canonical_finality_proof_line_chirho(proof_chirho)?;
    Ok(DigestChirho(
        blake3::hash(line_chirho.as_bytes()).to_hex().to_string(),
    ))
}

impl FinalityProofChirho {
    /// Law (i)'s locator half: the proof names EXACTLY the claim's burn (five-way equality; the
    /// proof ref itself is checked by content address, not here).
    pub fn matches_burn_ref_chirho(&self, burn_chirho: &FinalBurnRefChirho) -> bool {
        self.source_money_group_chirho == burn_chirho.source_money_group_chirho
            && self.source_cluster_chirho == burn_chirho.source_cluster_chirho
            && self.source_epoch_chirho == burn_chirho.source_epoch_chirho
            && self.source_seq_chirho == burn_chirho.source_seq_chirho
            && self.source_record_digest_chirho == burn_chirho.source_record_digest_chirho
    }

    /// Law (i)'s burn-summary half: every duplicated claim field EQUALS the proof's bound burn
    /// evidence (amount, kind revision, src, dst money-group/cluster/account, channel).
    pub fn matches_claim_chirho(&self, claim_chirho: &CounterpartClaimChirho) -> bool {
        self.burn_amount_chirho == claim_chirho.amount_chirho
            && self.burn_kind_policy_ref_chirho == claim_chirho.kind_policy_ref_chirho
            && self.burn_src_chirho == claim_chirho.src_chirho
            && self.burn_dst_money_group_chirho == claim_chirho.dst_money_group_chirho
            && self.burn_dst_cluster_chirho == claim_chirho.dst_cluster_chirho
            && self.burn_dst_chirho == claim_chirho.dst_chirho
            && self.burn_channel_chirho == claim_chirho.channel_chirho
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::counterpart_chirho::CounterpartNullifierChirho;
    use crate::LogIdChirho;

    fn sample_proof_chirho() -> FinalityProofChirho {
        FinalityProofChirho {
            schema_chirho: FINALITY_PROOF_SCHEMA_V1_CHIRHO.into(),
            source_money_group_chirho: MoneyGroupIdChirho("mg-1-chirho".into()),
            source_cluster_chirho: ClusterIdChirho("cluster-src-chirho".into()),
            source_epoch_chirho: 1,
            source_seq_chirho: 7,
            source_record_digest_chirho: DigestChirho("burn-digest-chirho".into()),
            cut_chirho: RetainedCutChirho {
                cut_epoch_chirho: 1,
                cut_seq_chirho: 9,
                cut_record_digest_chirho: DigestChirho("cut-digest-chirho".into()),
            },
            burn_amount_chirho: 25,
            burn_kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                "policy-money-chirho".into(),
            )),
            burn_src_chirho: LogIdChirho::new_chirho("alice-chirho", "money-chirho"),
            burn_dst_money_group_chirho: MoneyGroupIdChirho("mg-1-chirho".into()),
            burn_dst_cluster_chirho: ClusterIdChirho("cluster-dst-chirho".into()),
            burn_dst_chirho: LogIdChirho::new_chirho("bob-chirho", "money-chirho"),
            burn_channel_chirho: SettlementChannelIdChirho("chan-1-chirho".into()),
            root_sig_chirho: "root-sig-fixture-chirho".into(),
        }
    }

    #[test]
    fn canonical_roundtrip_and_ref_stability_chirho() {
        let proof_chirho = sample_proof_chirho();
        let line_chirho = canonical_finality_proof_line_chirho(&proof_chirho).unwrap();
        let parsed_chirho = parse_canonical_finality_proof_line_chirho(&line_chirho).unwrap();
        assert_eq!(parsed_chirho, proof_chirho);
        let ref_a_chirho = derive_finality_proof_ref_chirho(&proof_chirho).unwrap();
        let ref_b_chirho = derive_finality_proof_ref_chirho(&parsed_chirho).unwrap();
        assert_eq!(
            ref_a_chirho, ref_b_chirho,
            "one signed proof, one content identity"
        );
        // A RE-SIGNED proof is a DIFFERENT content identity (the ref binds sig included)...
        let mut resigned_chirho = proof_chirho.clone();
        resigned_chirho.root_sig_chirho = "another-sig-chirho".into();
        assert_ne!(
            derive_finality_proof_ref_chirho(&resigned_chirho).unwrap(),
            ref_a_chirho
        );
        // ...while the NULLIFIER (derived from claim coordinates, proof EXCLUDED) is untouched by
        // proof identity — the newer-proof re-mint attack has no coordinate to mint (#4395 pin).
        let nullifier_chirho = CounterpartNullifierChirho::derive_chirho(
            &proof_chirho.source_money_group_chirho,
            &proof_chirho.source_cluster_chirho,
            proof_chirho.source_epoch_chirho,
            proof_chirho.source_seq_chirho,
            &proof_chirho.source_record_digest_chirho,
            &proof_chirho.burn_dst_money_group_chirho,
            &proof_chirho.burn_dst_cluster_chirho,
            &proof_chirho.burn_dst_chirho,
            &proof_chirho.burn_channel_chirho,
        );
        let same_for_resigned_chirho = CounterpartNullifierChirho::derive_chirho(
            &resigned_chirho.source_money_group_chirho,
            &resigned_chirho.source_cluster_chirho,
            resigned_chirho.source_epoch_chirho,
            resigned_chirho.source_seq_chirho,
            &resigned_chirho.source_record_digest_chirho,
            &resigned_chirho.burn_dst_money_group_chirho,
            &resigned_chirho.burn_dst_cluster_chirho,
            &resigned_chirho.burn_dst_chirho,
            &resigned_chirho.burn_channel_chirho,
        );
        assert_eq!(nullifier_chirho, same_for_resigned_chirho);
    }

    #[test]
    fn cut_law_and_malleability_refuse_chirho() {
        // cut_seq < source_seq refuses at emit AND at parse.
        let mut early_cut_chirho = sample_proof_chirho();
        early_cut_chirho.cut_chirho.cut_seq_chirho = 3;
        assert!(canonical_finality_proof_line_chirho(&early_cut_chirho).is_err());
        let line_chirho = canonical_finality_proof_line_chirho(&sample_proof_chirho()).unwrap();
        let doctored_chirho =
            line_chirho.replacen("\"cut_seq_chirho\":9", "\"cut_seq_chirho\":3", 1);
        assert!(parse_canonical_finality_proof_line_chirho(&doctored_chirho).is_err());
        // The malleability family.
        for mutated_chirho in [
            format!(" {line_chirho}"),
            format!("{line_chirho}x"),
            line_chirho.replacen(
                "\"schema_chirho\"",
                "\"injected_chirho\":true,\"schema_chirho\"",
                1,
            ),
            line_chirho.replacen(
                FINALITY_PROOF_SCHEMA_V1_CHIRHO,
                "ledger-finality-proof-v9-chirho",
                1,
            ),
        ] {
            assert!(
                parse_canonical_finality_proof_line_chirho(&mutated_chirho).is_err(),
                "mutated proof must refuse: {mutated_chirho:.60}"
            );
        }
    }

    #[test]
    fn binding_predicates_fire_per_field_chirho() {
        use crate::counterpart_chirho::{CounterpartClaimChirho, FinalBurnRefChirho};
        let proof_chirho = sample_proof_chirho();
        let burn_chirho = FinalBurnRefChirho {
            source_money_group_chirho: proof_chirho.source_money_group_chirho.clone(),
            source_cluster_chirho: proof_chirho.source_cluster_chirho.clone(),
            source_epoch_chirho: proof_chirho.source_epoch_chirho,
            source_seq_chirho: proof_chirho.source_seq_chirho,
            source_record_digest_chirho: proof_chirho.source_record_digest_chirho.clone(),
            finality_proof_ref_chirho: derive_finality_proof_ref_chirho(&proof_chirho).unwrap(),
        };
        assert!(proof_chirho.matches_burn_ref_chirho(&burn_chirho));
        let mut skewed_chirho = burn_chirho.clone();
        skewed_chirho.source_seq_chirho = 8;
        assert!(!proof_chirho.matches_burn_ref_chirho(&skewed_chirho));
        let claim_chirho = CounterpartClaimChirho {
            transfer_id_chirho: crate::ids_chirho::TransferIdChirho("t-1-chirho".into()),
            burn_chirho,
            amount_chirho: proof_chirho.burn_amount_chirho,
            kind_policy_ref_chirho: proof_chirho.burn_kind_policy_ref_chirho.clone(),
            src_chirho: proof_chirho.burn_src_chirho.clone(),
            dst_money_group_chirho: proof_chirho.burn_dst_money_group_chirho.clone(),
            dst_cluster_chirho: proof_chirho.burn_dst_cluster_chirho.clone(),
            dst_chirho: proof_chirho.burn_dst_chirho.clone(),
            channel_chirho: proof_chirho.burn_channel_chirho.clone(),
            nullifier_chirho: CounterpartNullifierChirho::derive_chirho(
                &proof_chirho.source_money_group_chirho,
                &proof_chirho.source_cluster_chirho,
                proof_chirho.source_epoch_chirho,
                proof_chirho.source_seq_chirho,
                &proof_chirho.source_record_digest_chirho,
                &proof_chirho.burn_dst_money_group_chirho,
                &proof_chirho.burn_dst_cluster_chirho,
                &proof_chirho.burn_dst_chirho,
                &proof_chirho.burn_channel_chirho,
            ),
        };
        assert!(proof_chirho.matches_claim_chirho(&claim_chirho));
        let mut amount_skew_chirho = claim_chirho.clone();
        amount_skew_chirho.amount_chirho = 26;
        assert!(!proof_chirho.matches_claim_chirho(&amount_skew_chirho));
        let mut channel_skew_chirho = claim_chirho.clone();
        channel_skew_chirho.channel_chirho = SettlementChannelIdChirho("chan-2-chirho".into());
        assert!(!proof_chirho.matches_claim_chirho(&channel_skew_chirho));
    }
}
